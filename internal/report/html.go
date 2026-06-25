// Package report generates self-contained HTML and JSON reports for standalone mode.
// All CSS and JS is inline; the one exception is a Google Fonts CDN link for
// IBM Plex Mono, which degrades gracefully to Courier New/monospace offline.
package report

import (
	"bytes"
	"html/template"
	"sort"
	"time"

	"github.com/specter-demo/specter-scanner/internal/types"
)

// ReportData holds the structured data passed to the HTML template.
type ReportData struct {
	Title         string
	GeneratedAt   string
	Version       string
	OrgID         string
	ScanID        string

	TotalAgents   int
	ShadowAgents  int
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	TotalFindings int

	Agents   []AgentRow
	Findings []FindingRow
}

// AgentRow is a flat row for the agent inventory table.
type AgentRow struct {
	Name            string
	Platform        string
	VisibilityClass string
	FunctionalClass string
	RiskScore       int
	Framework       string
	FindingCount    int
	IsShadow        bool
}

// FindingRow is a flat row for the findings list.
type FindingRow struct {
	Severity    string
	RuleID      string
	AgentName   string
	Title       string
	Description string
	Plugin      string
}

// GenerateHTML produces a self-contained HTML report from a ScanPayload.
func GenerateHTML(payload types.ScanPayload, version string) ([]byte, error) {
	data := buildReportData(payload, version)

	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"visClass": visibilityClass,
		"sevClass": severityClass,
	}).Parse(htmlTemplate)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func buildReportData(payload types.ScanPayload, version string) ReportData {
	// Count findings by severity
	sevCount := map[string]int{}
	for _, f := range payload.Findings {
		sevCount[f.Severity]++
	}

	// Count findings per agent
	agentFindingCount := map[string]int{}
	for _, f := range payload.Findings {
		agentFindingCount[f.AgentStableID]++
	}

	// Build agent rows
	agents := make([]AgentRow, 0, len(payload.Agents))
	shadowCount := 0
	for _, a := range payload.Agents {
		row := AgentRow{
			Name:            a.Name,
			Platform:        a.Platform,
			VisibilityClass: string(a.VisibilityClass),
			FunctionalClass: string(a.FunctionalClass),
			RiskScore:       a.RiskScore,
			Framework:       a.Framework,
			FindingCount:    agentFindingCount[a.StableID],
			IsShadow:        a.IsShadow,
		}
		agents = append(agents, row)
		if a.IsShadow {
			shadowCount++
		}
	}
	// Sort by risk score descending
	sort.Slice(agents, func(i, j int) bool { return agents[i].RiskScore > agents[j].RiskScore })

	// Build finding rows — sorted CRITICAL > HIGH > MEDIUM > LOW
	sevOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
	findings := make([]FindingRow, 0, len(payload.Findings))
	for _, f := range payload.Findings {
		findings = append(findings, FindingRow{
			Severity:    f.Severity,
			RuleID:      f.RuleID,
			AgentName:   f.AgentName,
			Title:       f.Title,
			Description: f.Description,
			Plugin:      f.Plugin,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		oi := sevOrder[findings[i].Severity]
		oj := sevOrder[findings[j].Severity]
		if oi != oj {
			return oi < oj
		}
		return findings[i].AgentName < findings[j].AgentName
	})

	orgID := payload.OrgID
	if orgID == "" {
		orgID = "standalone"
	}

	return ReportData{
		Title:         "Specter Scanner Report",
		GeneratedAt:   time.Now().UTC().Format("2 January 2006 15:04 UTC"),
		Version:       version,
		OrgID:         orgID,
		ScanID:        payload.ScanID,
		TotalAgents:   len(payload.Agents),
		ShadowAgents:  shadowCount,
		CriticalCount: sevCount["CRITICAL"],
		HighCount:     sevCount["HIGH"],
		MediumCount:   sevCount["MEDIUM"],
		LowCount:      sevCount["LOW"],
		TotalFindings: len(payload.Findings),
		Agents:        agents,
		Findings:      findings,
	}
}

func visibilityClass(v string) string {
	switch v {
	case "SHADOW":
		return "vis-shadow"
	case "GOVERNED":
		return "vis-governed"
	case "DISCOVERED":
		return "vis-discovered"
	case "UNREGISTERED":
		return "vis-unregistered"
	default:
		return ""
	}
}

func severityClass(s string) string {
	switch s {
	case "CRITICAL":
		return "sev-critical"
	case "HIGH":
		return "sev-high"
	case "MEDIUM":
		return "sev-medium"
	case "LOW":
		return "sev-low"
	default:
		return "sev-info"
	}
}

// CountBySeverity returns the number of findings matching the given severity.
func CountBySeverity(findings []types.FindingRecord, severity string) int {
	n := 0
	for _, f := range findings {
		if f.Severity == severity {
			n++
		}
	}
	return n
}

// htmlTemplate is the self-contained HTML report template.
// All CSS/JS is inline except the IBM Plex Mono Google Fonts link (see head).
const htmlTemplate = `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}, {{.GeneratedAt}}</title>
<!-- Optional external dependency: IBM Plex Mono. The report remains fully
     functional offline — font-family falls back to Courier New / monospace
     if these requests fail or are blocked (e.g. air-gapped environments). -->
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root {
  --navy:    #1B2A4A;
  --blue:    #2E5FA3;
  --mint:    #50C8B4;
  --accent:  #7C6AF7;
  --critical: #E03030;
  --high:    #E07B00;
  --medium:  #D4A017;
  --low:     #2E8A5E;
  --bg:      #0A0F1A;
  --surface: #111827;
  --surface2: #18213A;
  --border:  #1E2D45;
  --border2: #243358;
  --text:    #E8EDF5;
  --text2:   #8B9BB4;
  --text3:   #536481;
}
/* Light mode — only background/surface/border/text tokens change.
   Severity colors, accent, and mint are semantically fixed across modes. */
[data-theme="light"] {
  --bg:       #F2F2F5;
  --surface:  #FFFFFF;
  --surface2: #F0F2F7;
  --border:   #E0E0EA;
  --border2:  #C8C8DA;
  --text:     #0C0C10;
  --text2:    #46465A;
  --text3:    #84849A;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: 'IBM Plex Mono', 'Courier New', monospace;
  font-size: 13px;
  line-height: 1.6;
  padding: 0 0 64px;
}
a { color: var(--mint); text-decoration: none; }

/* ── Header ── */
header {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 28px 40px 24px;
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 24px;
}
.wordmark {
  font-size: 20px;
  font-weight: 700;
  letter-spacing: 0.14em;
  color: var(--text);
}
.wordmark span { color: var(--mint); }
.scan-meta {
  font-size: 11px;
  color: var(--text3);
  margin-top: 6px;
  letter-spacing: 0.04em;
}
.header-right { text-align: right; }
.report-title {
  font-size: 15px;
  font-weight: 600;
  color: var(--text);
  letter-spacing: 0.02em;
}
.report-date { font-size: 11px; color: var(--text3); margin-top: 4px; }

/* ── Layout ── */
.container { max-width: 1100px; margin: 0 auto; padding: 0 40px; }

/* ── Metrics strip ── */
.metrics {
  display: flex;
  gap: 1px;
  background: var(--border);
  border-bottom: 1px solid var(--border);
  margin-bottom: 40px;
}
.metric {
  flex: 1;
  background: var(--surface);
  padding: 24px 28px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.metric-value {
  font-size: 36px;
  font-weight: 700;
  line-height: 1;
  color: var(--text);
}
.metric-value.crit { color: var(--critical); }
.metric-value.high { color: var(--high); }
.metric-value.shadow { color: #E879F9; }
.metric-label {
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--text3);
}

/* ── Sections ── */
section { margin-bottom: 48px; }
.section-label {
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: var(--text3);
  margin-bottom: 16px;
}

/* ── Tables ── */
.table-wrap {
  border: 1px solid var(--border);
  border-radius: 4px;
  overflow: hidden;
}
table { width: 100%; border-collapse: collapse; }
thead th {
  background: var(--surface2);
  padding: 10px 14px;
  text-align: left;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--text3);
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
tbody tr { border-bottom: 1px solid var(--border); }
tbody tr:last-child { border-bottom: none; }
tbody tr:hover { background: var(--surface2); }
tbody td { padding: 10px 14px; color: var(--text); vertical-align: middle; }
.agent-name { font-weight: 600; color: var(--text); }
.agent-sub { font-size: 11px; color: var(--text3); margin-top: 2px; }

/* ── Visibility badges ── */
.badge {
  display: inline-block;
  padding: 2px 7px;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  border-radius: 3px;
}
.vis-shadow     { background: rgba(232,121,249,0.18); color: #E879F9; }
.vis-governed   { background: rgba(46,138,94,0.18);  color: #50C878; }
.vis-discovered { background: rgba(212,160,23,0.18); color: #D4A017; }
.vis-unregistered { background: rgba(90,90,112,0.25); color: #9B9BB8; }

/* ── Severity badges ── */
.sev-critical { background: rgba(224,48,48,0.18); color: var(--critical); }
.sev-high     { background: rgba(224,123,0,0.18); color: var(--high); }
.sev-medium   { background: rgba(212,160,23,0.18); color: var(--medium); }
.sev-low      { background: rgba(46,138,94,0.18);  color: var(--low); }
.sev-info     { background: rgba(139,155,180,0.18); color: var(--text3); }

/* ── Risk score bar ── */
.risk-score { display: flex; align-items: center; gap: 8px; }
.risk-bar { flex: 1; height: 4px; background: var(--border2); border-radius: 2px; }
.risk-fill { height: 100%; border-radius: 2px; }
.risk-fill.r-crit  { background: var(--critical); }
.risk-fill.r-high  { background: var(--high); }
.risk-fill.r-med   { background: var(--medium); }
.risk-fill.r-low   { background: var(--low); }

/* ── Findings ── */
.finding {
  border: 1px solid var(--border);
  border-radius: 4px;
  margin-bottom: 8px;
  overflow: hidden;
}
.finding-header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 16px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
}
.finding-body { padding: 12px 16px; background: var(--bg); }
.finding-desc { color: var(--text2); margin-bottom: 8px; }
.finding-agent {
  font-size: 11px;
  color: var(--text3);
  margin-left: auto;
}
.finding-rule {
  font-size: 11px;
  font-weight: 600;
  color: var(--text2);
  letter-spacing: 0.04em;
}

/* ── Severity group headers ── */
.sev-group { margin-bottom: 24px; }
.sev-group-header {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 10px;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--border);
}
.sev-group-title {
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.06em;
  text-transform: uppercase;
}
.sev-group-count { font-size: 11px; color: var(--text3); }

/* ── No findings ── */
.empty { text-align: center; padding: 48px 24px; color: var(--text3); }

/* ── Footer ── */
footer {
  margin-top: 64px;
  border-top: 1px solid var(--border);
  padding: 28px 40px;
  background: var(--surface);
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 32px;
}
.footer-left .footer-brand { font-weight: 700; letter-spacing: 0.1em; color: var(--text); margin-bottom: 4px; }
.footer-left p { font-size: 11px; color: var(--text3); }
.footer-right { text-align: right; }
.footer-cta { font-size: 12px; color: var(--text2); margin-bottom: 4px; }
.footer-cta strong { color: var(--mint); }
.footer-right p { font-size: 11px; color: var(--text3); }

/* ── Header controls (theme toggle / PDF download) ── */
.header-controls { display: flex; gap: 8px; justify-content: flex-end; margin-bottom: 10px; }
.icon-btn {
  background: var(--surface2);
  border: 1px solid var(--border2);
  color: var(--text2);
  font-family: inherit;
  font-size: 11px;
  letter-spacing: 0.04em;
  padding: 4px 10px;
  border-radius: 4px;
  cursor: pointer;
}
.icon-btn:hover { background: var(--border); color: var(--text); }

/* ── Print stylesheet (used by the Download PDF button via window.print()) ── */
@media print {
  @page {
    margin: 0;
  }
  body {
    padding: 1.5cm;
  }
  #themeToggle, #downloadBtn { display: none; }
  body { background: #fff; color: #000; }
  .finding { page-break-inside: avoid; }
  .metric  { page-break-inside: avoid; }
  :root {
    --bg: #FFFFFF; --surface: #F8F8F8; --surface2: #F0F2F7;
    --border: #E0E0EA; --text: #0C0C10; --text2: #46465A; --text3: #84849A;
  }
}
</style>
</head>
<body>

<header>
  <div>
    <div class="wordmark"><span>SPECTER</span> SCANNER</div>
    <div class="scan-meta">
      Scan ID: {{.ScanID}} &nbsp;·&nbsp; Org: {{.OrgID}} &nbsp;·&nbsp; {{.GeneratedAt}}
    </div>
  </div>
  <div class="header-right">
    <div class="header-controls">
      <button id="themeToggle" class="icon-btn" type="button" title="Toggle light/dark mode">☀</button>
      <button id="downloadBtn" class="icon-btn" type="button" title="Download as PDF">PDF ⬇</button>
    </div>
    <div class="report-title">Security Scan Report</div>
    <div class="report-date">specter-scanner {{.Version}}</div>
  </div>
</header>

<div class="metrics">
  <div class="metric">
    <span class="metric-value">{{.TotalAgents}}</span>
    <span class="metric-label">Agents Discovered</span>
  </div>
  <div class="metric">
    <span class="metric-value crit">{{.CriticalCount}}</span>
    <span class="metric-label">Critical Findings</span>
  </div>
  <div class="metric">
    <span class="metric-value high">{{.HighCount}}</span>
    <span class="metric-label">High Findings</span>
  </div>
  <div class="metric">
    <span class="metric-value">{{.TotalFindings}}</span>
    <span class="metric-label">Total Findings</span>
  </div>
  <div class="metric">
    <span class="metric-value shadow">{{.ShadowAgents}}</span>
    <span class="metric-label">Shadow Agents</span>
  </div>
</div>

<div class="container">

  <!-- ── Agent Inventory ── -->
  <section>
    <div class="section-label">Agent Inventory</div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Agent</th>
            <th>Platform</th>
            <th>Visibility</th>
            <th>Risk</th>
            <th>Framework</th>
            <th>Findings</th>
          </tr>
        </thead>
        <tbody>
          {{range .Agents}}
          <tr>
            <td>
              <div class="agent-name">{{.Name}}</div>
              <div class="agent-sub">{{.FunctionalClass}}</div>
            </td>
            <td><span class="badge sev-info">{{.Platform}}</span></td>
            <td><span class="badge {{visClass .VisibilityClass}}">{{.VisibilityClass}}</span></td>
            <td>
              <div class="risk-score">
                <span>{{.RiskScore}}</span>
                <div class="risk-bar">
                  {{if ge .RiskScore 75}}<div class="risk-fill r-crit" style="width:{{.RiskScore}}%"></div>
                  {{else if ge .RiskScore 50}}<div class="risk-fill r-high" style="width:{{.RiskScore}}%"></div>
                  {{else if ge .RiskScore 25}}<div class="risk-fill r-med" style="width:{{.RiskScore}}%"></div>
                  {{else}}<div class="risk-fill r-low" style="width:{{.RiskScore}}%"></div>
                  {{end}}
                </div>
              </div>
            </td>
            <td>{{if .Framework}}{{.Framework}}{{else}}<span style="color:var(--text3)">—</span>{{end}}</td>
            <td>{{if gt .FindingCount 0}}<strong>{{.FindingCount}}</strong>{{else}}0{{end}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
    </div>
  </section>

  <!-- ── Findings ── -->
  <section>
    <div class="section-label">Findings ({{.TotalFindings}})</div>

    {{if eq .TotalFindings 0}}
    <div class="empty">✓ No findings — clean posture for this scan.</div>
    {{else}}

    <!-- CRITICAL -->
    {{if gt .CriticalCount 0}}
    <div class="sev-group">
      <div class="sev-group-header">
        <span class="badge sev-critical">CRITICAL</span>
        <span class="sev-group-count">{{.CriticalCount}} finding{{if gt .CriticalCount 1}}s{{end}}</span>
      </div>
      {{range .Findings}}{{if eq .Severity "CRITICAL"}}
      <div class="finding">
        <div class="finding-header">
          <span class="badge sev-critical">{{.Severity}}</span>
          <span class="finding-rule">{{.RuleID}}</span>
          <span class="finding-agent">{{.AgentName}}</span>
        </div>
        <div class="finding-body">
          <div class="finding-desc">{{.Title}}</div>
          {{if .Description}}<div style="font-size:12px;color:var(--text3)">{{.Description}}</div>{{end}}
        </div>
      </div>
      {{end}}{{end}}
    </div>
    {{end}}

    <!-- HIGH -->
    {{if gt .HighCount 0}}
    <div class="sev-group">
      <div class="sev-group-header">
        <span class="badge sev-high">HIGH</span>
        <span class="sev-group-count">{{.HighCount}} finding{{if gt .HighCount 1}}s{{end}}</span>
      </div>
      {{range .Findings}}{{if eq .Severity "HIGH"}}
      <div class="finding">
        <div class="finding-header">
          <span class="badge sev-high">{{.Severity}}</span>
          <span class="finding-rule">{{.RuleID}}</span>
          <span class="finding-agent">{{.AgentName}}</span>
        </div>
        <div class="finding-body">
          <div class="finding-desc">{{.Title}}</div>
          {{if .Description}}<div style="font-size:12px;color:var(--text3)">{{.Description}}</div>{{end}}
        </div>
      </div>
      {{end}}{{end}}
    </div>
    {{end}}

    <!-- MEDIUM -->
    {{if gt .MediumCount 0}}
    <div class="sev-group">
      <div class="sev-group-header">
        <span class="badge sev-medium">MEDIUM</span>
        <span class="sev-group-count">{{.MediumCount}} finding{{if gt .MediumCount 1}}s{{end}}</span>
      </div>
      {{range .Findings}}{{if eq .Severity "MEDIUM"}}
      <div class="finding">
        <div class="finding-header">
          <span class="badge sev-medium">{{.Severity}}</span>
          <span class="finding-rule">{{.RuleID}}</span>
          <span class="finding-agent">{{.AgentName}}</span>
        </div>
        <div class="finding-body">
          <div class="finding-desc">{{.Title}}</div>
          {{if .Description}}<div style="font-size:12px;color:var(--text3)">{{.Description}}</div>{{end}}
        </div>
      </div>
      {{end}}{{end}}
    </div>
    {{end}}

    <!-- LOW -->
    {{if gt .LowCount 0}}
    <div class="sev-group">
      <div class="sev-group-header">
        <span class="badge sev-low">LOW</span>
        <span class="sev-group-count">{{.LowCount}} finding{{if gt .LowCount 1}}s{{end}}</span>
      </div>
      {{range .Findings}}{{if eq .Severity "LOW"}}
      <div class="finding">
        <div class="finding-header">
          <span class="badge sev-low">{{.Severity}}</span>
          <span class="finding-rule">{{.RuleID}}</span>
          <span class="finding-agent">{{.AgentName}}</span>
        </div>
        <div class="finding-body">
          <div class="finding-desc">{{.Title}}</div>
          {{if .Description}}<div style="font-size:12px;color:var(--text3)">{{.Description}}</div>{{end}}
        </div>
      </div>
      {{end}}{{end}}
    </div>
    {{end}}

    {{end}}
  </section>

</div><!-- /container -->

<footer>
  <div class="footer-left">
    <div class="footer-brand">SPECTER SCANNER</div>
    <p>Generated by specter-scanner {{.Version}}, open source AI agent security scanner</p>
    <p style="margin-top:4px">Apache 2.0 license &nbsp;·&nbsp; github.com/specter-demo/specter-scanner</p>
  </div>
  <div class="footer-right">
    <div class="footer-cta">
      For a full governance dashboard, compliance reports,<br>
      and AI-powered risk analysis: <strong>spectersystems.ai</strong>
    </div>
    <p>Connect the Specter Platform for CISO-grade reporting and team collaboration.</p>
  </div>
</footer>

<script>
(function() {
  var btn = document.getElementById('themeToggle');
  btn.addEventListener('click', function() {
    var html = document.documentElement;
    var current = html.getAttribute('data-theme') || 'dark';
    var next = current === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', next);
    btn.textContent = next === 'dark' ? '☀' : '☾';
  });
})();
(function() {
  var dlBtn = document.getElementById('downloadBtn');
  dlBtn.addEventListener('click', function() {
    window.print();
  });
})();
</script>

</body>
</html>`
