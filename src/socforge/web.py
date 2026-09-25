import html
import sqlite3

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse


app = FastAPI(title="SOC-Forge")


def get_connection():
    connection = sqlite3.connect("socforge.db")
    connection.row_factory = sqlite3.Row
    return connection


def get_alerts(
    severity: str | None = None,
    source_ip: str | None = None,
    rule_id: str | None = None,
):
    connection = get_connection()

    try:
        query = """
            SELECT
                id,
                rule_id,
                severity,
                source_ip,
                message,
                event_message,
                timestamp
            FROM alerts
            WHERE 1 = 1
        """

        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)

        if rule_id:
            query += " AND rule_id = ?"
            params.append(rule_id)

        query += " ORDER BY id DESC"

        rows = connection.execute(query, params).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def get_alert(alert_id: int):
    connection = get_connection()

    try:
        row = connection.execute(
            """
            SELECT
                id,
                rule_id,
                severity,
                source_ip,
                message,
                event_message,
                timestamp
            FROM alerts
            WHERE id = ?
            """,
            (alert_id,),
        ).fetchone()

        return dict(row) if row else None

    finally:
        connection.close()


def get_incident_evidence(alert: dict):
    connection = get_connection()

    try:
        if alert["rule_id"] == "AUTH-002":
            rows = connection.execute(
                """
                SELECT
                    id,
                    source_ip,
                    event_message,
                    timestamp
                FROM alerts
                WHERE rule_id = 'AUTH-001'
                  AND source_ip = ?
                ORDER BY id ASC
                """,
                (alert["source_ip"],),
            ).fetchall()

            return [dict(row) for row in rows]

        return [
            {
                "id": alert["id"],
                "source_ip": alert["source_ip"],
                "event_message": alert["event_message"],
                "timestamp": alert["timestamp"],
            }
        ]

    finally:
        connection.close()


def get_stats():
    connection = get_connection()

    try:
        total = connection.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        high = connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'high'"
        ).fetchone()[0]

        medium = connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'medium'"
        ).fetchone()[0]

        unique_ips = connection.execute(
            """
            SELECT COUNT(DISTINCT source_ip)
            FROM alerts
            WHERE source_ip IS NOT NULL
            """
        ).fetchone()[0]

        rules = connection.execute(
            """
            SELECT COUNT(DISTINCT rule_id)
            FROM alerts
            """
        ).fetchone()[0]

        return total, high, medium, unique_ips, rules

    finally:
        connection.close()


def get_rule_stats():
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT rule_id, COUNT(*) AS total
            FROM alerts
            GROUP BY rule_id
            ORDER BY total DESC
            """
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def get_recent_alerts(limit: int = 5):
    connection = get_connection()

    try:
        rows = connection.execute(
            """
            SELECT
                id,
                rule_id,
                severity,
                source_ip,
                message,
                timestamp
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


@app.get("/", response_class=HTMLResponse)
def dashboard(
    severity: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    rule_id: str | None = Query(default=None),
):
    alerts = get_alerts(
        severity=severity,
        source_ip=source_ip,
        rule_id=rule_id,
    )

    total, high, medium, unique_ips, rules = get_stats()

    rule_stats = get_rule_stats()
    recent_alerts = get_recent_alerts()

    max_rule_count = max(
        (item["total"] for item in rule_stats),
        default=1,
    )

    chart_rows = ""

    for item in rule_stats:
        percentage = int(
            (item["total"] / max_rule_count) * 100
        )

        chart_rows += f"""
        <div class="chart-row">
            <div class="chart-label">
                {html.escape(item["rule_id"])}
            </div>

            <div class="chart-track">
                <div
                    class="chart-bar"
                    style="width: {percentage}%"
                ></div>
            </div>

            <div class="chart-value">
                {item["total"]}
            </div>
        </div>
        """

    threat_feed = ""

    for alert in recent_alerts:
        severity_class = html.escape(alert["severity"])

        threat_feed += f"""
        <div class="feed-item">

            <div class="feed-main">

                <span class="feed-dot {severity_class}"></span>

                <div>

                    <div class="feed-title">
                        {html.escape(alert["rule_id"])}
                        <span class="feed-ip">
                            {html.escape(alert["source_ip"] or "N/A")}
                        </span>
                    </div>

                    <div class="feed-message">
                        {html.escape(alert["message"])}
                    </div>

                </div>

            </div>

            <div class="feed-time">
                {html.escape(alert["timestamp"])}
            </div>

        </div>
        """

    rows = ""

    for alert in alerts:
        severity_class = html.escape(alert["severity"])

        rows += f"""
        <tr>

            <td>
                <a
                    href="/incidents/{alert["id"]}"
                    class="incident-link"
                >
                    #{alert["id"]}
                </a>
            </td>

            <td class="rule">
                {html.escape(alert["rule_id"])}
            </td>

            <td>
                <span class="badge {severity_class}">
                    <span class="badge-dot"></span>
                    {html.escape(alert["severity"].upper())}
                </span>
            </td>

            <td class="mono">
                {html.escape(alert["source_ip"] or "N/A")}
            </td>

            <td class="message-cell">
                {html.escape(alert["message"])}
            </td>

            <td class="mono muted timestamp-cell">
                {html.escape(alert["timestamp"])}
            </td>

        </tr>
        """

    return f"""
    <!DOCTYPE html>
    <html lang="es">

    <head>

        <meta charset="UTF-8">

        <meta
            http-equiv="refresh"
            content="10"
        >

        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >

        <title>SOC-Forge</title>

        <style>

            :root {{
                --bg: #070b11;
                --panel: rgba(17, 24, 34, 0.80);
                --border: rgba(120, 170, 220, 0.18);
                --border-strong: rgba(77, 163, 255, 0.40);

                --text: #eef6ff;
                --muted: #7f8da0;

                --blue: #4da3ff;
                --green: #62e6a7;
                --red: #ff5e73;
                --yellow: #f4c95d;
            }}

            * {{
                box-sizing: border-box;
            }}

            body {{
                margin: 0;
                min-height: 100vh;
                padding: 34px;

                font-family:
                    Inter,
                    ui-sans-serif,
                    system-ui,
                    -apple-system,
                    BlinkMacSystemFont,
                    "Segoe UI",
                    sans-serif;

                color: var(--text);

                background:
                    radial-gradient(
                        circle at 10% 0%,
                        rgba(77, 163, 255, 0.12),
                        transparent 28%
                    ),
                    radial-gradient(
                        circle at 90% 10%,
                        rgba(98, 230, 167, 0.05),
                        transparent 24%
                    ),
                    linear-gradient(
                        180deg,
                        #070b11 0%,
                        #090e15 100%
                    );

                overflow-x: hidden;
            }}

            body::before {{
                content: "";
                position: fixed;
                inset: 0;
                pointer-events: none;

                background-image:
                    linear-gradient(
                        rgba(255,255,255,0.025) 1px,
                        transparent 1px
                    ),
                    linear-gradient(
                        90deg,
                        rgba(255,255,255,0.025) 1px,
                        transparent 1px
                    );

                background-size: 40px 40px;

                mask-image:
                    linear-gradient(
                        to bottom,
                        black 0%,
                        rgba(0,0,0,.7) 50%,
                        transparent 100%
                    );
            }}

            .shell {{
                position: relative;
                z-index: 1;

                max-width: 1450px;
                margin: 0 auto;
            }}

            .top-line {{
                height: 2px;
                margin-bottom: 26px;

                background:
                    linear-gradient(
                        90deg,
                        transparent,
                        var(--blue),
                        transparent
                    );

                box-shadow:
                    0 0 18px rgba(77,163,255,.6);
            }}

            .header {{
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                gap: 20px;

                margin-bottom: 28px;
            }}

            .brand {{
                display: flex;
                align-items: center;
                gap: 16px;
            }}

            .brand-icon {{
                width: 52px;
                height: 52px;

                display: grid;
                place-items: center;

                border-radius: 15px;

                background:
                    linear-gradient(
                        180deg,
                        rgba(77,163,255,.18),
                        rgba(77,163,255,.05)
                    );

                border: 1px solid var(--border-strong);

                box-shadow:
                    0 0 30px rgba(77,163,255,.15),
                    inset 0 0 18px rgba(77,163,255,.07);

                font-size: 26px;
            }}

            .title {{
                margin: 0;
                font-size: 38px;
                letter-spacing: -.03em;
            }}

            .subtitle {{
                margin-top: 5px;
                color: var(--muted);
                font-size: 14px;
            }}

            .system-area {{
                display: flex;
                flex-direction: column;
                align-items: flex-end;
                gap: 8px;
            }}

            .system-status {{
                display: inline-flex;
                align-items: center;
                gap: 9px;

                padding: 10px 14px;

                border: 1px solid rgba(98,230,167,.24);
                border-radius: 999px;

                background: rgba(98,230,167,.06);

                color: var(--green);

                font-size: 12px;
                font-weight: 800;

                letter-spacing: .04em;

                box-shadow:
                    0 0 22px rgba(98,230,167,.06);
            }}

            .status-dot {{
                width: 8px;
                height: 8px;
                border-radius: 50%;

                background: var(--green);

                box-shadow:
                    0 0 8px var(--green),
                    0 0 18px rgba(98,230,167,.5);

                animation: pulse 1.8s infinite;
            }}

            .engine-meta {{
                color: #66788c;

                font-family:
                    "JetBrains Mono",
                    "SFMono-Regular",
                    Consolas,
                    monospace;

                font-size: 10px;
            }}

            @keyframes pulse {{
                0%,100% {{
                    transform: scale(1);
                    opacity: 1;
                }}

                50% {{
                    transform: scale(1.35);
                    opacity: .65;
                }}
            }}

            .cards {{
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 16px;
            }}

            .card {{
                position: relative;
                overflow: hidden;

                padding: 21px;

                background:
                    linear-gradient(
                        145deg,
                        rgba(22,31,44,.92),
                        rgba(14,20,29,.92)
                    );

                border: 1px solid var(--border);
                border-radius: 16px;

                box-shadow:
                    0 18px 50px rgba(0,0,0,.28);

                transition:
                    transform .18s ease,
                    border-color .18s ease,
                    box-shadow .18s ease;
            }}

            .card:hover {{
                transform: translateY(-3px);

                border-color: var(--border-strong);

                box-shadow:
                    0 18px 50px rgba(0,0,0,.30),
                    0 0 30px rgba(77,163,255,.08);
            }}

            .card::before {{
                content: "";

                position: absolute;
                inset: 0 0 auto;

                height: 2px;

                background:
                    linear-gradient(
                        90deg,
                        transparent,
                        rgba(77,163,255,.8),
                        transparent
                    );
            }}

            .card h2 {{
                margin: 0;

                font-size: 34px;
                letter-spacing: -.03em;
            }}

            .card p {{
                margin: 8px 0 0;

                color: var(--muted);

                font-size: 13px;
                text-transform: uppercase;
                letter-spacing: .08em;
            }}

            .panel {{
                margin-top: 20px;
                padding: 21px;

                background: var(--panel);

                border: 1px solid var(--border);
                border-radius: 16px;

                backdrop-filter: blur(18px);

                box-shadow:
                    0 18px 50px rgba(0,0,0,.22);
            }}

            .panel h3 {{
                margin: 0;

                font-size: 15px;
                letter-spacing: .04em;
            }}

            .chart-row {{
                display: grid;

                grid-template-columns:
                    90px
                    minmax(150px, 1fr)
                    42px;

                gap: 14px;
                align-items: center;

                margin-top: 16px;
            }}

            .chart-label {{
                color: #9bacc0;

                font-family:
                    "JetBrains Mono",
                    "SFMono-Regular",
                    Consolas,
                    monospace;

                font-size: 12px;
            }}

            .chart-track {{
                position: relative;
                overflow: hidden;

                height: 16px;

                border-radius: 999px;

                background: #080d13;

                border: 1px solid rgba(120,170,220,.14);
            }}

            .chart-bar {{
                height: 100%;

                border-radius: inherit;

                background:
                    linear-gradient(
                        90deg,
                        #2f82ff,
                        #62b4ff
                    );

                box-shadow:
                    0 0 10px rgba(77,163,255,.55),
                    0 0 24px rgba(77,163,255,.16);
            }}

            .chart-value {{
                text-align: right;
                font-size: 13px;
                font-weight: 800;
            }}

            .feed-panel {{
                position: relative;
                overflow: hidden;
            }}

            .feed-panel::after {{
                content: "LIVE";

                position: absolute;
                top: 20px;
                right: 20px;

                padding: 5px 8px;

                border-radius: 999px;

                border: 1px solid rgba(98,230,167,.2);

                color: var(--green);

                font-size: 9px;
                font-weight: 900;
                letter-spacing: .08em;

                background: rgba(98,230,167,.05);
            }}

            .feed-item {{
                display: flex;
                justify-content: space-between;
                gap: 18px;

                padding: 14px 0;

                border-bottom: 1px solid rgba(120,170,220,.08);
            }}

            .feed-item:last-child {{
                border-bottom: none;
                padding-bottom: 0;
            }}

            .feed-main {{
                display: flex;
                align-items: flex-start;
                gap: 11px;
                min-width: 0;
            }}

            .feed-dot {{
                flex: 0 0 auto;

                width: 8px;
                height: 8px;

                margin-top: 6px;

                border-radius: 50%;
            }}

            .feed-dot.high {{
                background: var(--red);

                box-shadow:
                    0 0 8px var(--red),
                    0 0 16px rgba(255,94,115,.25);
            }}

            .feed-dot.medium {{
                background: var(--yellow);

                box-shadow:
                    0 0 8px var(--yellow);
            }}

            .feed-title {{
                font-family:
                    "JetBrains Mono",
                    "SFMono-Regular",
                    Consolas,
                    monospace;

                font-size: 12px;
                font-weight: 800;
            }}

            .feed-ip {{
                margin-left: 10px;

                color: #67b4ff;
                font-weight: 500;
            }}

            .feed-message {{
                margin-top: 4px;

                color: #94a5b8;

                font-size: 12px;
            }}

            .feed-time {{
                flex: 0 0 auto;

                color: #617287;

                font-family:
                    "JetBrains Mono",
                    "SFMono-Regular",
                    Consolas,
                    monospace;

                font-size: 10px;

                text-align: right;
            }}

            .filters {{
                display: flex;
                flex-wrap: wrap;
                gap: 10px;

                margin-top: 16px;
            }}

            select,
            input,
            button {{
                min-height: 40px;

                padding: 10px 12px;

                border-radius: 10px;

                border: 1px solid var(--border);

                background: rgba(8,13,19,.9);

                color: var(--text);

                outline: none;
            }}

            input {{
                min-width: 220px;
            }}

            button {{
                cursor: pointer;
                font-weight: 800;
            }}

            button:hover {{
                border-color: rgba(77,163,255,.5);

                box-shadow:
                    0 0 18px rgba(77,163,255,.08);
            }}

            .table-wrap {{
                margin-top: 20px;

                overflow-x: auto;

                border-radius: 16px;

                border: 1px solid var(--border);

                background: rgba(13,18,26,.84);

                box-shadow:
                    0 18px 50px rgba(0,0,0,.28);
            }}

            table {{
                width: 100%;
                min-width: 1100px;

                border-collapse: collapse;
            }}

            th,
            td {{
                padding: 15px 14px;

                text-align: left;

                border-bottom:
                    1px solid rgba(120,170,220,.08);
            }}

            th {{
                color: #6f8196;

                font-size: 11px;
                font-weight: 800;

                letter-spacing: .08em;
                text-transform: uppercase;

                background:
                    rgba(255,255,255,.015);
            }}

            tbody tr {{
                transition:
                    background .16s ease,
                    box-shadow .16s ease;
            }}

            tbody tr:hover {{
                background: rgba(77,163,255,.035);

                box-shadow:
                    inset 3px 0 0 rgba(77,163,255,.45);
            }}

            tr:last-child td {{
                border-bottom: none;
            }}

            .incident-link {{
                color: #67b4ff;

                text-decoration: none;

                font-weight: 800;

                text-shadow:
                    0 0 10px rgba(77,163,255,.18);
            }}

            .incident-link:hover {{
                color: #a4d9ff;
            }}

            .rule,
            .mono {{
                font-family:
                    "JetBrains Mono",
                    "SFMono-Regular",
                    Consolas,
                    monospace;
            }}

            .message-cell {{
                min-width: 370px;
                max-width: 650px;
                line-height: 1.45;
            }}

            .timestamp-cell {{
                min-width: 235px;
            }}

            .muted {{
                color: #77879a;
                font-size: 11px;
            }}

            .badge {{
                display: inline-flex;
                align-items: center;
                gap: 7px;

                padding: 6px 9px;

                border-radius: 999px;

                font-size: 11px;
                font-weight: 900;
                letter-spacing: .05em;
            }}

            .badge-dot {{
                width: 7px;
                height: 7px;
                border-radius: 50%;
            }}

            .badge.high {{
                color: #ff7182;

                background: rgba(255,94,115,.13);

                border: 1px solid rgba(255,94,115,.22);

                box-shadow:
                    0 0 16px rgba(255,94,115,.07);
            }}

            .badge.high .badge-dot {{
                background: var(--red);

                box-shadow:
                    0 0 8px var(--red);
            }}

            .badge.medium {{
                color: #f5d06a;

                background: rgba(244,201,93,.12);

                border: 1px solid rgba(244,201,93,.18);
            }}

            .badge.medium .badge-dot {{
                background: var(--yellow);

                box-shadow:
                    0 0 8px var(--yellow);
            }}

            .footer {{
                display: flex;
                justify-content: space-between;
                align-items: center;

                margin-top: 20px;

                color: #59697a;

                font-size: 10px;
            }}

            .footer-left {{
                font-family:
                    "JetBrains Mono",
                    "SFMono-Regular",
                    Consolas,
                    monospace;
            }}

            @media (max-width: 1050px) {{
                .cards {{
                    grid-template-columns: repeat(2, 1fr);
                }}
            }}

            @media (max-width: 700px) {{

                body {{
                    padding: 18px;
                }}

                .header {{
                    flex-direction: column;
                }}

                .system-area {{
                    align-items: flex-start;
                }}

                .cards {{
                    grid-template-columns: 1fr;
                }}

                .feed-item {{
                    flex-direction: column;
                }}

                .feed-time {{
                    text-align: left;
                }}

                .chart-row {{
                    grid-template-columns: 74px 1fr 30px;
                }}

            }}

        </style>

    </head>

    <body>

        <div class="shell">

            <div class="top-line"></div>

            <header class="header">

                <div class="brand">

                    <div class="brand-icon">
                        🛡️
                    </div>

                    <div>

                        <h1 class="title">
                            SOC-Forge
                        </h1>

                        <div class="subtitle">
                            Security Operations Center
                            · Local Detection Platform
                        </div>

                    </div>

                </div>

                <div class="system-area">

                    <div class="system-status">
                        <span class="status-dot"></span>
                        SYSTEM ONLINE
                    </div>

                    <div class="engine-meta">
                        ENGINE: ONLINE
                        · RULES: {rules}
                        · IPS: {unique_ips}
                    </div>

                </div>

            </header>

            <section class="cards">

                <div class="card">
                    <h2>{total}</h2>
                    <p>Total Alerts</p>
                </div>

                <div class="card">
                    <h2>{high}</h2>
                    <p>High Severity</p>
                </div>

                <div class="card">
                    <h2>{medium}</h2>
                    <p>Medium Severity</p>
                </div>

                <div class="card">
                    <h2>{unique_ips}</h2>
                    <p>Unique Source IPs</p>
                </div>

            </section>

            <section class="panel">

                <h3>
                    Detection Activity
                </h3>

                {chart_rows}

            </section>

            <section class="panel feed-panel">

                <h3>
                    Live Threat Feed
                </h3>

                {threat_feed}

            </section>

            <section class="panel">

                <h3>
                    Detection Filters
                </h3>

                <form
                    method="get"
                    class="filters"
                >

                    <select name="severity">

                        <option value="">
                            All severities
                        </option>

                        <option value="high">
                            High
                        </option>

                        <option value="medium">
                            Medium
                        </option>

                    </select>

                    <select name="rule_id">

                        <option value="">
                            All rules
                        </option>

                        <option value="AUTH-001">
                            AUTH-001
                        </option>

                        <option value="AUTH-002">
                            AUTH-002
                        </option>

                    </select>

                    <input
                        type="text"
                        name="source_ip"
                        placeholder="Source IP"
                    >

                    <button type="submit">
                        Filter
                    </button>

                    <a href="/">

                        <button type="button">
                            Reset
                        </button>

                    </a>

                </form>

            </section>

            <section class="table-wrap">

                <table>

                    <thead>

                        <tr>
                            <th>ID</th>
                            <th>Rule</th>
                            <th>Severity</th>
                            <th>Source IP</th>
                            <th>Message</th>
                            <th>Timestamp</th>
                        </tr>

                    </thead>

                    <tbody>

                        {rows}

                    </tbody>

                </table>

            </section>

            <footer class="footer">

                <div class="footer-left">
                    SOC-FORGE // DETECTION ENGINE ONLINE
                </div>

                <div>
                    AUTO-REFRESH · 10 SECONDS
                </div>

            </footer>

        </div>

    </body>

    </html>
    """


@app.get("/incidents/{alert_id}", response_class=HTMLResponse)
def incident(alert_id: int):

    alert = get_alert(alert_id)

    if not alert:
        return HTMLResponse(
            content="""
            <h1>Incident not found</h1>
            <a href="/">Return to dashboard</a>
            """,
            status_code=404,
        )

    evidence = get_incident_evidence(alert)

    severity_class = html.escape(
        alert["severity"]
    )

    evidence_rows = ""

    for item in evidence:

        evidence_rows += f"""
        <div class="evidence-item">

            <div class="evidence-time">
                {html.escape(item["timestamp"])}
            </div>

            <div class="evidence-ip">
                {html.escape(item["source_ip"] or "N/A")}
            </div>

            <pre>{html.escape(item["event_message"])}</pre>

        </div>
        """

    failed_attempts = len(evidence)

    return f"""
    <!DOCTYPE html>
    <html lang="es">

    <head>

        <meta charset="UTF-8">

        <meta
            name="viewport"
            content="width=device-width, initial-scale=1.0"
        >

        <title>
            Incident #{alert["id"]} · SOC-Forge
        </title>

        <style>

            :root {{
                --bg: #070b11;
                --panel: rgba(17,24,34,.84);
                --border: rgba(120,170,220,.18);
                --blue: #4da3ff;
                --red: #ff5e73;
                --yellow: #f4c95d;
                --text: #eef6ff;
                --muted: #7f8da0;
            }}

            * {{
                box-sizing: border-box;
            }}

            body {{
                margin: 0;
                min-height: 100vh;
                padding: 34px;

                font-family:
                    Inter,
                    ui-sans-serif,
                    system-ui,
                    sans-serif;

                color: var(--text);

                background:
                    radial-gradient(
                        circle at 12% 0%,
                        rgba(77,163,255,.12),
                        transparent 28%
                    ),
                    linear-gradient(
                        180deg,
                        #070b11 0%,
                        #090e15 100%
                    );
            }}

            .shell {{
                max-width: 1050px;
                margin: 0 auto;
            }}

            .top-line {{
                height: 2px;
                margin-bottom: 24px;

                background:
                    linear-gradient(
                        90deg,
                        transparent,
                        var(--blue),
                        transparent
                    );

                box-shadow:
                    0 0 18px rgba(77,163,255,.5);
            }}

            .back {{
                color: #67b4ff;
                text-decoration: none;
                font-size: 13px;
            }}

            .header {{
                margin-top: 24px;
                padding: 26px;

                background: var(--panel);

                border: 1px solid var(--border);
                border-radius: 16px;

                box-shadow:
                    0 18px 50px rgba(0,0,0,.28);
            }}

            .header-row {{
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                gap: 20px;
            }}

            .title {{
                margin: 0;
                font-size: 34px;
            }}

            .message {{
                margin-top: 8px;
                color: #a8b6c8;
            }}

            .severity {{
                padding: 9px 12px;

                border-radius: 999px;

                font-size: 12px;
                font-weight: 900;
                letter-spacing: .06em;
            }}

            .severity.high {{
                color: var(--red);

                background: rgba(255,94,115,.10);

                border: 1px solid rgba(255,94,115,.22);

                box-shadow:
                    0 0 18px rgba(255,94,115,.08);
            }}

            .severity.medium {{
                color: var(--yellow);

                background: rgba(244,201,93,.08);

                border: 1px solid rgba(244,201,93,.18);
            }}

            .grid {{
                display: grid;
                grid-template-columns: repeat(2,1fr);
                gap: 16px;

                margin-top: 18px;
            }}

            .box {{
                padding: 20px;

                background: var(--panel);

                border: 1px solid var(--border);
                border-radius: 16px;

                box-shadow:
                    0 14px 38px rgba(0,0,0,.20);
            }}

            .label {{
                color: var(--muted);

                font-size: 11px;
                font-weight: 800;
                letter-spacing: .08em;
                text-transform: uppercase;
            }}

            .value {{
                margin-top: 8px;
                font-size: 19px;
            }}

            .mono {{
                font-family:
                    "JetBrains Mono",
                    "SFMono-Regular",
                    Consolas,
                    monospace;
            }}

            .evidence {{
                margin-top: 18px;
            }}

            .evidence-item {{
                margin-top: 12px;
                padding: 16px;

                background: rgba(8,13,19,.92);

                border: 1px solid rgba(120,170,220,.12);
                border-radius: 12px;
            }}

            .evidence-time {{
                color: #8192a5;
                font-size: 11px;
            }}

            .evidence-ip {{
                margin-top: 5px;

                color: #67b4ff;

                font-family:
                    "JetBrains Mono",
                    "SFMono-Regular",
                    Consolas,
                    monospace;

                font-size: 12px;
            }}

            pre {{
                white-space: pre-wrap;
                word-break: break-word;

                margin: 10px 0 0;

                color: #e7eef7;

                font-family:
                    "JetBrains Mono",
                    "SFMono-Regular",
                    Consolas,
                    monospace;

                font-size: 12px;
                line-height: 1.55;
            }}

            @media (max-width: 700px) {{

                body {{
                    padding: 18px;
                }}

                .header-row {{
                    flex-direction: column;
                }}

                .grid {{
                    grid-template-columns: 1fr;
                }}

            }}

        </style>

    </head>

    <body>

        <div class="shell">

            <div class="top-line"></div>

            <a href="/" class="back">
                ← Back to dashboard
            </a>

            <section class="header">

                <div class="header-row">

                    <div>

                        <h1 class="title">
                            Incident #{alert["id"]}
                        </h1>

                        <div class="message">
                            {html.escape(alert["message"])}
                        </div>

                    </div>

                    <div class="severity {severity_class}">
                        {html.escape(alert["severity"].upper())}
                    </div>

                </div>

            </section>

            <section class="grid">

                <div class="box">

                    <div class="label">
                        Detection Rule
                    </div>

                    <div class="value mono">
                        {html.escape(alert["rule_id"])}
                    </div>

                </div>

                <div class="box">

                    <div class="label">
                        Source IP
                    </div>

                    <div class="value mono">
                        {html.escape(alert["source_ip"] or "N/A")}
                    </div>

                </div>

                <div class="box">

                    <div class="label">
                        Detected At
                    </div>

                    <div class="value mono">
                        {html.escape(alert["timestamp"])}
                    </div>

                </div>

                <div class="box">

                    <div class="label">
                        Related Failed Attempts
                    </div>

                    <div class="value">
                        {failed_attempts}
                    </div>

                </div>

            </section>

            <section class="box evidence">

                <div class="label">
                    Evidence
                </div>

                {evidence_rows}

            </section>

        </div>

    </body>

    </html>
    """


@app.get("/api/alerts")
def alerts_api(
    severity: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    rule_id: str | None = Query(default=None),
):
    return get_alerts(
        severity=severity,
        source_ip=source_ip,
        rule_id=rule_id,
    )