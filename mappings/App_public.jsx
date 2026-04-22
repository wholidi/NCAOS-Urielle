import { useState, useEffect } from "react";

const EVENTS = [
  {
    id: 1,
    event_type: "policy_violation",
    timestamp: "2026-04-02T10:15:00Z",
    action_taken: "blocked",
    affected_layer: "boundary",
  },
  {
    id: 2,
    event_type: "unauthorized_access",
    timestamp: "2026-04-02T10:20:00Z",
    action_taken: "denied",
    affected_layer: "boundary",
  },
  {
    id: 3,
    event_type: "state_anomaly",
    timestamp: "2026-04-02T10:25:00Z",
    action_taken: "restricted",
    affected_layer: "boundary",
  },
  {
    id: 4,
    event_type: "integrity_breach",
    timestamp: "2026-04-02T10:30:00Z",
    action_taken: "shutdown",
    affected_layer: "boundary",
  },
];

const CONTROL_MAP = {
  policy_violation: {
    severity: "HIGH",
    control_category: "Governance & Accountability",
    audit_finding:
      "Boundary-emitted signal interpreted as a governance-relevant control event.",
    reference_group: ["Control Reference A", "Control Reference B"],
    analyst_actions: [
      "Log event",
      "Review policy alignment",
      "Escalate if recurring",
    ],
    gap_flag: null,
  },
  unauthorized_access: {
    severity: "CRITICAL",
    control_category: "Security & Access Control",
    audit_finding:
      "Boundary-emitted signal interpreted as a security-relevant control event.",
    reference_group: ["Control Reference A", "Control Reference B"],
    analyst_actions: [
      "Record access denial",
      "Review external interaction context",
      "Flag for investigation",
    ],
    gap_flag: "Additional identity / session context may improve audit depth",
  },
  state_anomaly: {
    severity: "MEDIUM",
    control_category: "System Stability",
    audit_finding:
      "Boundary-emitted signal interpreted as a stability or anomaly-related control event.",
    reference_group: ["Control Reference A", "Control Reference B"],
    analyst_actions: [
      "Track anomaly occurrence",
      "Review operational baseline",
      "Monitor recurrence",
    ],
    gap_flag: "Additional baseline context may improve interpretation depth",
  },
  integrity_breach: {
    severity: "CRITICAL",
    control_category: "System Integrity",
    audit_finding:
      "Boundary-emitted signal interpreted as a high-severity integrity-related control event.",
    reference_group: ["Control Reference A", "Control Reference B"],
    analyst_actions: [
      "Open incident record",
      "Preserve event chain",
      "Trigger integrity review",
    ],
    gap_flag: null,
  },
};

const SEVERITY_COLOR = {
  CRITICAL: {
    bg: "#1a0000",
    border: "#ff2a2a",
    text: "#ff7070",
    dot: "#ff2a2a",
    glow: "rgba(255,42,42,0.22)",
  },
  HIGH: {
    bg: "#1a1000",
    border: "#ff9800",
    text: "#ffbc5e",
    dot: "#ff9800",
    glow: "rgba(255,152,0,0.18)",
  },
  MEDIUM: {
    bg: "#111400",
    border: "#b7d400",
    text: "#d4ef58",
    dot: "#b7d400",
    glow: "rgba(183,212,0,0.18)",
  },
};

function buildAuditResults() {
  return EVENTS.map((event) => {
    const mapping = CONTROL_MAP[event.event_type];
    return {
      event_id: event.id,
      event_type: event.event_type,
      timestamp: event.timestamp,
      action_taken: event.action_taken,
      affected_layer: event.affected_layer,
      severity: mapping.severity,
      control_category: mapping.control_category,
      audit_finding: mapping.audit_finding,
      reference_group: mapping.reference_group,
      analyst_actions: mapping.analyst_actions,
      gap_flag: mapping.gap_flag,
    };
  });
}

function downloadFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function exportJSON() {
  const results = buildAuditResults();
  downloadFile(
    "audit_results_public_demo.json",
    JSON.stringify(results, null, 2),
    "application/json"
  );
}

function exportCSV() {
  const results = buildAuditResults();
  const headers = [
    "event_id",
    "event_type",
    "timestamp",
    "action_taken",
    "affected_layer",
    "severity",
    "control_category",
    "audit_finding",
    "reference_group",
    "analyst_actions",
    "gap_flag",
  ];

  const escapeCSV = (value) => {
    if (value === null || value === undefined) return "";
    const str = Array.isArray(value) ? value.join(" | ") : String(value);
    return `"${str.replace(/"/g, '""')}"`;
  };

  const rows = results.map((row) =>
    headers.map((header) => escapeCSV(row[header])).join(",")
  );

  const csv = [headers.join(","), ...rows].join("\n");
  downloadFile("audit_results_public_demo.csv", csv, "text/csv;charset=utf-8;");
}

function MetricCard({ label, value, color }) {
  return (
    <div
      style={{
        border: "1px solid #181818",
        background: "#090909",
        borderRadius: 6,
        padding: "14px 16px",
        minHeight: 82,
      }}
    >
      <div
        style={{
          fontSize: 9,
          fontFamily: "monospace",
          color: "#4a4a4a",
          letterSpacing: 2,
          marginBottom: 10,
          textTransform: "uppercase",
        }}
      >
        {label}
      </div>
      <div
        style={{
          fontSize: 28,
          fontFamily: "monospace",
          color,
          lineHeight: 1,
        }}
      >
        {value}
      </div>
    </div>
  );
}

function EventCard({ event, isSelected, onClick, isProcessed }) {
  const mapping = CONTROL_MAP[event.event_type];
  const sc = SEVERITY_COLOR[mapping.severity];

  return (
    <div
      onClick={onClick}
      style={{
        border: `1px solid ${isSelected ? sc.border : "#222"}`,
        borderRadius: 6,
        padding: "14px 14px 12px",
        cursor: "pointer",
        background: isSelected ? sc.bg : "#0a0a0a",
        transition: "all 0.2s ease",
        position: "relative",
        overflow: "hidden",
        boxShadow: isSelected ? `0 0 0 1px ${sc.glow}, 0 0 18px ${sc.glow}` : "none",
      }}
    >
      <div
        style={{
          position: "absolute",
          inset: 0,
          background:
            "linear-gradient(90deg, rgba(255,255,255,0.015) 0%, rgba(255,255,255,0) 30%)",
          pointerEvents: "none",
        }}
      />
      {isProcessed && (
        <div
          style={{
            position: "absolute",
            top: 8,
            right: 10,
            fontSize: 10,
            color: "#5dff9f",
            letterSpacing: 1,
            fontFamily: "monospace",
          }}
        >
          ✓ MAPPED
        </div>
      )}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          marginBottom: 6,
        }}
      >
        <div
          style={{
            width: 8,
            height: 8,
            borderRadius: "50%",
            background: sc.dot,
            boxShadow: `0 0 8px ${sc.dot}`,
          }}
        />
        <span
          style={{
            fontFamily: "monospace",
            fontSize: 12,
            color: sc.text,
            letterSpacing: 1.2,
            textTransform: "uppercase",
            fontWeight: 700,
          }}
        >
          {event.event_type.replaceAll("_", " ")}
        </span>
      </div>

      <div
        style={{
          fontFamily: "monospace",
          fontSize: 10,
          color: "#555",
          marginBottom: 8,
        }}
      >
        {event.timestamp}
      </div>

      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        <span
          style={{
            fontSize: 9,
            fontFamily: "monospace",
            color: "#7a7a7a",
            border: "1px solid #202020",
            borderRadius: 3,
            padding: "3px 6px",
            background: "#0d0d0d",
          }}
        >
          action: {event.action_taken}
        </span>
        <span
          style={{
            fontSize: 9,
            fontFamily: "monospace",
            color: "#7a7a7a",
            border: "1px solid #202020",
            borderRadius: 3,
            padding: "3px 6px",
            background: "#0d0d0d",
          }}
        >
          layer: {event.affected_layer}
        </span>
      </div>
    </div>
  );
}

function SectionLabel({ children }) {
  return (
    <div
      style={{
        fontSize: 9,
        fontFamily: "monospace",
        color: "#4a4a4a",
        letterSpacing: 2,
        marginBottom: 10,
        textTransform: "uppercase",
      }}
    >
      {children}
    </div>
  );
}

function AuditPanel({ event, mapping }) {
  const sc = SEVERITY_COLOR[mapping.severity];
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    setVisible(false);
    const t = setTimeout(() => setVisible(true), 60);
    return () => clearTimeout(t);
  }, [event.id]);

  return (
    <div
      style={{
        opacity: visible ? 1 : 0,
        transform: visible ? "translateY(0)" : "translateY(8px)",
        transition: "all 0.3s ease",
      }}
    >
      <div
        style={{
          border: "1px solid #171717",
          borderRadius: 8,
          padding: "18px 20px",
          background:
            "linear-gradient(180deg, rgba(18,18,18,1) 0%, rgba(8,8,8,1) 100%)",
        }}
      >
        <div
          style={{
            borderBottom: "1px solid #171717",
            paddingBottom: 14,
            marginBottom: 18,
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              marginBottom: 6,
              flexWrap: "wrap",
            }}
          >
            <div
              style={{
                padding: "4px 10px",
                borderRadius: 3,
                background: sc.bg,
                border: `1px solid ${sc.border}`,
                fontFamily: "monospace",
                fontSize: 11,
                color: sc.text,
                letterSpacing: 2,
                fontWeight: 700,
              }}
            >
              {mapping.severity}
            </div>
            <span
              style={{
                fontFamily: "'Courier New', monospace",
                fontSize: 13,
                color: "#9a9a9a",
                letterSpacing: 1,
              }}
            >
              {mapping.control_category}
            </span>
          </div>

          <div
            style={{
              fontFamily: "monospace",
              fontSize: 10,
              color: "#3a3a3a",
            }}
          >
            INCIDENT · {event.event_type.toUpperCase().replace("_", " ")} ·{" "}
            {event.timestamp}
          </div>
        </div>

        <div style={{ marginBottom: 20 }}>
          <SectionLabel>Audit Finding</SectionLabel>
          <div
            style={{
              fontSize: 13,
              color: "#c4c4c4",
              lineHeight: 1.75,
              fontFamily: "'Georgia', serif",
              borderLeft: `2px solid ${sc.border}`,
              paddingLeft: 14,
            }}
          >
            {mapping.audit_finding}
          </div>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: 18,
            marginBottom: 20,
          }}
        >
          <div>
            <SectionLabel>Reference Group</SectionLabel>
            {mapping.reference_group.map((ref) => (
              <div
                key={ref}
                style={{
                  fontFamily: "monospace",
                  fontSize: 11,
                  color: "#8ca2ff",
                  marginBottom: 5,
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}
              >
                <span style={{ color: "#3e4e7a" }}>›</span> {ref}
              </div>
            ))}
          </div>

          <div>
            <SectionLabel>Interpretation Mode</SectionLabel>
            <div
              style={{
                fontFamily: "monospace",
                fontSize: 11,
                color: "#8ca2ff",
                lineHeight: 1.6,
              }}
            >
              Boundary signal → audit interpretation → control-aligned output
            </div>
          </div>
        </div>

        <div style={{ marginBottom: 18 }}>
          <SectionLabel>Recommended Analyst Actions</SectionLabel>
          {mapping.analyst_actions.map((a, i) => (
            <div
              key={i}
              style={{
                display: "flex",
                gap: 10,
                marginBottom: 7,
                alignItems: "flex-start",
              }}
            >
              <span
                style={{
                  fontFamily: "monospace",
                  fontSize: 10,
                  color: "#4e67b4",
                  marginTop: 2,
                  minWidth: 18,
                }}
              >
                {String(i + 1).padStart(2, "0")}
              </span>
              <span style={{ fontSize: 12, color: "#979797", lineHeight: 1.55 }}>
                {a}
              </span>
            </div>
          ))}
        </div>

        {mapping.gap_flag ? (
          <div
            style={{
              border: "1px solid #3b2603",
              background: "#171000",
              borderRadius: 6,
              padding: "12px 14px",
              fontFamily: "monospace",
              fontSize: 11,
              color: "#c89b4d",
            }}
          >
            <span style={{ color: "#ff9f1a", marginRight: 8 }}>⚠</span>
            Optional Schema Enrichment: {mapping.gap_flag}
          </div>
        ) : (
          <div
            style={{
              border: "1px solid #10311d",
              background: "#08110c",
              borderRadius: 6,
              padding: "12px 14px",
              fontFamily: "monospace",
              fontSize: 11,
              color: "#5dff9f",
            }}
          >
            <span style={{ marginRight: 8 }}>✓</span>
            Signal sufficient for control-aligned interpretation
          </div>
        )}
      </div>
    </div>
  );
}

function ValidationVerdict({ processed }) {
  const total = EVENTS.length;
  const gaps = Object.values(CONTROL_MAP).filter((m) => m.gap_flag).length;
  const sufficient = total - gaps;

  return (
    <div
      style={{
        border: "1px solid #171717",
        borderRadius: 8,
        padding: "18px 20px",
        background: "#090909",
        marginTop: 18,
      }}
    >
      <SectionLabel>Validation Verdict · {processed}/{total} Events Reviewed</SectionLabel>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr 1fr",
          gap: 12,
          marginBottom: 16,
        }}
      >
        {[
          { label: "Events Mapped", value: total, color: "#5dff9f" },
          { label: "Full Signal", value: sufficient, color: "#55a9ff" },
          { label: "Optional Gaps", value: gaps, color: "#ff9f1a" },
        ].map((m) => (
          <div
            key={m.label}
            style={{
              textAlign: "center",
              border: "1px solid #171717",
              borderRadius: 6,
              padding: "12px 8px",
              background: "#050505",
            }}
          >
            <div
              style={{
                fontSize: 24,
                fontFamily: "monospace",
                color: m.color,
                marginBottom: 4,
              }}
            >
              {m.value}
            </div>
            <div
              style={{
                fontSize: 9,
                fontFamily: "monospace",
                color: "#4a4a4a",
                letterSpacing: 1,
              }}
            >
              {m.label.toUpperCase()}
            </div>
          </div>
        ))}
      </div>

      <div
        style={{
          fontSize: 12,
          color: "#888",
          lineHeight: 1.75,
          fontFamily: "'Georgia', serif",
          borderLeft: "2px solid #242424",
          paddingLeft: 14,
        }}
      >
        This public demo shows that boundary-emitted events can be interpreted into
        structured audit outputs while preserving separation between the originating
        system and the external assurance layer.
      </div>
    </div>
  );
}

export default function App() {
  const [selected, setSelected] = useState(null);
  const [processed, setProcessed] = useState(new Set());

  const handleSelect = (ev) => {
    setSelected(ev);
    setProcessed((prev) => new Set([...prev, ev.id]));
  };

  const criticalCount = Object.values(CONTROL_MAP).filter(
    (m) => m.severity === "CRITICAL"
  ).length;
  const highCount = Object.values(CONTROL_MAP).filter(
    (m) => m.severity === "HIGH"
  ).length;
  const gapCount = Object.values(CONTROL_MAP).filter((m) => m.gap_flag).length;

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#040404",
        color: "#ccc",
        padding: "24px 24px 30px",
        fontFamily: "Inter, monospace",
      }}
    >
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 18,
          gap: 12,
          flexWrap: "wrap",
        }}
      >
        <div>
          <div
            style={{
              fontSize: 9,
              letterSpacing: 3,
              color: "#3b3b3b",
              marginBottom: 7,
              textTransform: "uppercase",
              fontFamily: "monospace",
            }}
          >
            Public Demo · Boundary Signal Audit Interface
          </div>
          <div
            style={{
              fontSize: 22,
              color: "#dddddd",
              letterSpacing: -0.5,
              fontFamily: "'Georgia', serif",
              fontStyle: "italic",
            }}
          >
            Decoupled Assurance Monitor
          </div>
          <div
            style={{
              fontSize: 11,
              color: "#444",
              marginTop: 6,
              fontFamily: "monospace",
            }}
          >
            Illustrative interface validation view
          </div>
        </div>

        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button
            onClick={exportJSON}
            style={{
              background: "#09111e",
              color: "#7fb3ff",
              border: "1px solid #1c3558",
              borderRadius: 6,
              padding: "10px 14px",
              fontSize: 11,
              fontFamily: "monospace",
              cursor: "pointer",
            }}
          >
            Export JSON
          </button>
          <button
            onClick={exportCSV}
            style={{
              background: "#0a140c",
              color: "#7be59e",
              border: "1px solid #1f4d2f",
              borderRadius: 6,
              padding: "10px 14px",
              fontSize: 11,
              fontFamily: "monospace",
              cursor: "pointer",
            }}
          >
            Export CSV
          </button>
        </div>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, minmax(140px, 1fr))",
          gap: 12,
          marginBottom: 20,
        }}
      >
        <MetricCard label="Events In Queue" value={EVENTS.length} color="#d7d7d7" />
        <MetricCard label="Critical Signals" value={criticalCount} color="#ff6b6b" />
        <MetricCard label="High Severity" value={highCount} color="#ffb45d" />
        <MetricCard label="Optional Gaps" value={gapCount} color="#55a9ff" />
      </div>

      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 0,
          marginBottom: 22,
          fontSize: 10,
          color: "#333",
          fontFamily: "monospace",
          letterSpacing: 1,
          overflowX: "auto",
          paddingBottom: 2,
        }}
      >
        {[
          { label: "REQUEST", dim: true },
          { arrow: true },
          { label: "MIDDLEWARE" },
          { arrow: true },
          { label: "MODEL" },
          { arrow: true },
          { label: "BOUNDARY" },
          { arrow: true },
          { label: "AUDIT LAYER", active: true, sub: "EXTERNAL" },
          { arrow: true },
          { label: "ASSURANCE", dim: true },
        ].map((node, i) =>
          node.arrow ? (
            <span key={i} style={{ color: "#202020", margin: "0 4px" }}>
              →
            </span>
          ) : (
            <div
              key={i}
              style={{
                padding: "5px 10px",
                border: `1px solid ${node.active ? "#254893" : "#141414"}`,
                borderRadius: 4,
                background: node.active ? "#07101c" : "transparent",
                color: node.active ? "#6f9cff" : "#444",
                whiteSpace: "nowrap",
                textAlign: "center",
                minWidth: 78,
              }}
            >
              <div>{node.label}</div>
              {node.sub && (
                <div
                  style={{
                    fontSize: 8,
                    color: "#39579b",
                  }}
                >
                  {node.sub}
                </div>
              )}
            </div>
          )
        )}
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "300px 1fr 280px",
          gap: 18,
          alignItems: "start",
        }}
      >
        <div
          style={{
            border: "1px solid #161616",
            borderRadius: 8,
            background: "#070707",
            padding: "16px 14px",
          }}
        >
          <SectionLabel>Event Queue · {processed.size}/{EVENTS.length} Processed</SectionLabel>
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {EVENTS.map((ev) => (
              <EventCard
                key={ev.id}
                event={ev}
                isSelected={selected?.id === ev.id}
                isProcessed={processed.has(ev.id)}
                onClick={() => handleSelect(ev)}
              />
            ))}
          </div>
        </div>

        <div>
          {selected ? (
            <>
              <SectionLabel>Incident Detail · Audit Artifact Generated</SectionLabel>
              <AuditPanel
                event={selected}
                mapping={CONTROL_MAP[selected.event_type]}
              />
            </>
          ) : (
            <div
              style={{
                height: 360,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                border: "1px dashed #171717",
                borderRadius: 8,
                color: "#222",
                fontSize: 11,
                letterSpacing: 2,
                background: "#060606",
              }}
            >
              SELECT AN EVENT TO PROCESS
            </div>
          )}

          {processed.size === EVENTS.length && (
            <ValidationVerdict processed={processed.size} />
          )}
        </div>

        <div
          style={{
            border: "1px solid #161616",
            borderRadius: 8,
            background: "#070707",
            padding: "16px 14px",
          }}
        >
          <SectionLabel>Analyst Notes</SectionLabel>

          <div
            style={{
              border: "1px solid #191919",
              borderRadius: 6,
              padding: "12px 12px",
              marginBottom: 14,
              background: "#0a0a0a",
            }}
          >
            <div
              style={{
                fontSize: 9,
                fontFamily: "monospace",
                color: "#4a4a4a",
                letterSpacing: 2,
                textTransform: "uppercase",
                marginBottom: 8,
              }}
            >
              Current Assessment
            </div>
            <div
              style={{
                fontSize: 12,
                color: "#8c8c8c",
                lineHeight: 1.65,
              }}
            >
              Public-safe demonstration of how boundary-level events can be
              translated into external audit outputs without internal system access.
            </div>
          </div>

          <div
            style={{
              border: "1px solid #191919",
              borderRadius: 6,
              padding: "12px 12px",
              marginBottom: 14,
              background: "#0a0a0a",
            }}
          >
            <div
              style={{
                fontSize: 9,
                fontFamily: "monospace",
                color: "#4a4a4a",
                letterSpacing: 2,
                textTransform: "uppercase",
                marginBottom: 8,
              }}
            >
              Scope Note
            </div>
            <div style={{ fontSize: 12, color: "#8c8c8c", lineHeight: 1.65 }}>
              This demo uses illustrative control references and a simplified mapping
              layer. It is intended for interface demonstration only.
            </div>
          </div>

          <div
            style={{
              border: "1px solid #191919",
              borderRadius: 6,
              padding: "12px 12px",
              background: "#0a0a0a",
            }}
          >
            <div
              style={{
                fontSize: 9,
                fontFamily: "monospace",
                color: "#4a4a4a",
                letterSpacing: 2,
                textTransform: "uppercase",
                marginBottom: 8,
              }}
            >
              Demo Status
            </div>
            <div style={{ fontSize: 12, color: "#5dff9f", lineHeight: 1.65 }}>
              Public-safe showcase ready
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}