//go:build !slim

package cli

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/xerrors"

	"github.com/coder/coder/v2/codersdk"
	"github.com/coder/serpent"
	"github.com/coder/websocket"
)

// scaletestWorkspaceTrafficProbe is a diagnostic sibling of
// scaletestWorkspaceTraffic. It does not generate load; instead it reproduces
// the workspace-app connection setup used by the traffic test and reports, for
// each target, whether the app URL triggers an HTTP redirect and whether the
// production websocket dial succeeds.
//
// The traffic test's app runs fail on workspace-proxy regions with:
//
//	websocket dial: failed to WebSocket dial: failed to send handshake request:
//	Get ".../apps/wsec/": server redirected request from .../apps/wsec to .../apps/wsec/
//
// This command isolates that behavior so we can compare, from inside the
// deployment, the direct (coderd) path against the workspace-proxy path, with
// and without a trailing slash on the app URL. It is deployed the same way as
// the traffic test (same image and token) by swapping the Job command.
func (r *RootCmd) scaletestWorkspaceTrafficProbe() *serpent.Command {
	var (
		app               string
		workspaceProxyURL string
		count             int64
		iterations        int64
		iterationDelay    time.Duration

		targetFlags = &workspaceTargetFlags{}
	)

	cmd := &serpent.Command{
		Use:   "workspace-traffic-probe",
		Short: "Probe workspace-app connectivity to diagnose redirect/handshake failures",
		Long: "Reproduces the workspace-traffic app connection setup without generating load. " +
			"For each target workspace it builds the app URL the same way the traffic test does, " +
			"then reports whether a plain HTTP GET is redirected and whether the production " +
			"websocket dial succeeds, both without and with a trailing slash. When " +
			"--workspace-proxy-url is set it probes the proxy path (the failing case) alongside " +
			"the direct coderd path.",
		Handler: func(inv *serpent.Invocation) error {
			ctx := inv.Context()

			client, err := r.InitClient(inv)
			if err != nil {
				return err
			}

			me, err := RequireAdmin(ctx, client)
			if err != nil {
				return err
			}

			if app == "" {
				return xerrors.New("--app is required")
			}

			workspaces, err := targetFlags.getTargetedWorkspaces(ctx, client, me.OrganizationIDs, inv.Stdout)
			if err != nil {
				return err
			}
			if len(workspaces) == 0 {
				return xerrors.New("no target workspaces found")
			}

			appHost, err := client.AppHost(ctx)
			if err != nil {
				return xerrors.Errorf("get app host: %w", err)
			}

			// Optionally build a client that targets the workspace proxy, exactly
			// as the traffic test does.
			var webClient *codersdk.Client
			if workspaceProxyURL != "" {
				u, err := url.Parse(workspaceProxyURL)
				if err != nil {
					return xerrors.Errorf("parse workspace proxy URL: %w", err)
				}
				webClient = codersdk.New(u,
					codersdk.WithHTTPClient(client.HTTPClient),
					codersdk.WithSessionToken(client.SessionToken()),
				)
			}

			_, _ = fmt.Fprintf(inv.Stdout, "Probing %d workspace(s), app=%q, proxy=%q, iterations=%d\n\n",
				min(count, int64(len(workspaces))), app, workspaceProxyURL, iterations)

			var summary probeSummary
			for idx, ws := range workspaces {
				if int64(idx) >= count {
					break
				}

				var agent codersdk.WorkspaceAgent
				for _, res := range ws.LatestBuild.Resources {
					if len(res.Agents) == 0 {
						continue
					}
					agent = res.Agents[0]
				}
				if agent.ID == uuid.Nil {
					_, _ = fmt.Fprintf(inv.Stderr, "WARN: skipping workspace %s: no agent\n", ws.Name)
					continue
				}

				// Probe the direct (coderd) path.
				directCfg, err := createWorkspaceAppConfig(client, appHost.Host, app, ws, agent)
				if err != nil {
					return xerrors.Errorf("configure workspace app (direct): %w", err)
				}
				probeTarget(ctx, inv, &summary, "direct", client, directCfg.URL, iterations, iterationDelay)

				// Probe the workspace-proxy path (the failing case).
				if webClient != nil {
					proxyCfg, err := createWorkspaceAppConfig(webClient, appHost.Host, app, ws, agent)
					if err != nil {
						return xerrors.Errorf("configure workspace app (proxy): %w", err)
					}
					probeTarget(ctx, inv, &summary, "proxy", webClient, proxyCfg.URL, iterations, iterationDelay)
				}
			}

			_, _ = fmt.Fprintf(inv.Stdout, "\nSummary: httpRedirects=%d wsFailures=%d wsSuccesses=%d\n",
				summary.httpRedirects, summary.wsFailures, summary.wsSuccesses)
			return nil
		},
	}

	cmd.Options = serpent.OptionSet{
		{
			Flag:        "app",
			Env:         "CODER_SCALETEST_WORKSPACE_TRAFFIC_APP",
			Description: "Name of the workspace app to probe.",
			Value:       serpent.StringOf(&app),
		},
		{
			Flag:        "workspace-proxy-url",
			Env:         "CODER_SCALETEST_WORKSPACE_PROXY_URL",
			Description: "URL of a workspace proxy to probe in addition to the direct coderd path.",
			Value:       serpent.StringOf(&workspaceProxyURL),
		},
		{
			Flag:        "count",
			Default:     "1",
			Description: "Maximum number of target workspaces to probe.",
			Value:       serpent.Int64Of(&count),
		},
		{
			Flag:        "iterations",
			Default:     "3",
			Description: "Number of probe iterations per target (to catch intermittent failures).",
			Value:       serpent.Int64Of(&iterations),
		},
		{
			Flag:        "iteration-delay",
			Default:     "1s",
			Description: "Delay between probe iterations.",
			Value:       serpent.DurationOf(&iterationDelay),
		},
	}

	targetFlags.attach(&cmd.Options)

	return cmd
}

type probeSummary struct {
	httpRedirects int
	wsFailures    int
	wsSuccesses   int
}

// probeTarget runs both probes (HTTP redirect observation and production
// websocket dial) against baseURL and baseURL+"/", printing per-iteration
// results and updating the summary.
func probeTarget(ctx context.Context, inv *serpent.Invocation, summary *probeSummary, label string, client *codersdk.Client, baseURL string, iterations int64, delay time.Duration) {
	withSlash := baseURL
	if !strings.HasSuffix(withSlash, "/") {
		withSlash += "/"
	}

	_, _ = fmt.Fprintf(inv.Stdout, "[%s] %s\n", label, baseURL)
	for i := int64(0); i < iterations; i++ {
		for _, tc := range []struct {
			name string
			url  string
		}{
			{"no-slash", baseURL},
			{"slash", withSlash},
		} {
			status, loc, herr := httpProbe(ctx, client, tc.url)
			redirected := status >= 300 && status < 400
			if redirected {
				summary.httpRedirects++
			}
			httpMsg := fmt.Sprintf("http=%d", status)
			if herr != nil {
				httpMsg = fmt.Sprintf("http=err(%v)", herr)
			} else if loc != "" {
				httpMsg = fmt.Sprintf("http=%d -> %s", status, loc)
			}

			wsErr := wsProbe(ctx, client, tc.url)
			wsMsg := "ws=ok"
			if wsErr != nil {
				summary.wsFailures++
				wsMsg = fmt.Sprintf("ws=err(%v)", wsErr)
			} else {
				summary.wsSuccesses++
			}

			_, _ = fmt.Fprintf(inv.Stdout, "    iter=%d %-8s %-40s %s\n", i, tc.name, httpMsg, wsMsg)
		}
		if delay > 0 && i < iterations-1 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}
}

// httpProbe issues a GET that observes (does not follow) redirects, so we can
// see the exact Location the server returns. It reuses the client's transport
// and session token but overrides redirect handling.
func httpProbe(ctx context.Context, client *codersdk.Client, rawURL string) (status int, location string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, "", err
	}
	client.SessionTokenProvider.AsRequestOption()(req)

	httpClient := &http.Client{
		Transport: client.HTTPClient.Transport,
		// Observe redirects instead of following or rejecting them.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 15 * time.Second,
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, resp.Header.Get("Location"), nil
}

// wsProbe reproduces the production websocket dial from
// workspacetraffic.appClientConn, including the CLI client's redirect
// rejection, so a benign server redirect surfaces as the same failure the
// traffic test sees.
func wsProbe(ctx context.Context, client *codersdk.Client, rawURL string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	wsOptions := &websocket.DialOptions{
		HTTPClient: client.HTTPClient,
	}
	client.SessionTokenProvider.SetDialOption(wsOptions)

	//nolint:bodyclose // Closed below via conn.Close.
	conn, _, err := websocket.Dial(ctx, rawURL, wsOptions)
	if err != nil {
		return err
	}
	_ = conn.Close(websocket.StatusNormalClosure, "probe complete")
	return nil
}
