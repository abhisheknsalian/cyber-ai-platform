import { useState } from "react";

import { useThreatGraph } from "../../hooks/useThreatGraph";
import type { EntityType, RelationType } from "../../types/intelligence";

const VIEWBOX_SIZE = 360;
const CENTER = VIEWBOX_SIZE / 2;
const RADIUS = 140;

// Matches the severity/accent CSS custom properties already defined in
// frontend/src/index.css -- no new colors introduced, just reused with a different
// meaning here (entity type instead of severity).
const ENTITY_COLOR: Record<EntityType, string> = {
  threat: "var(--color-accent)",
  technique: "var(--color-severity-critical)",
  indicator: "var(--color-severity-medium)",
  mitigation: "var(--color-severity-low)",
  source: "var(--color-text-muted)",
};

const RELATION_LABEL: Record<RelationType, string> = {
  USES: "uses",
  HAS_INDICATOR: "indicator",
  MITIGATED_BY: "mitigated by",
  SUPPORTED_BY: "source",
};

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

interface Props {
  threatId: string;
}

/** A simple radial node-link diagram: the threat in the center, its direct graph
 * relationships (technique/indicator/mitigation/source) as surrounding nodes, drawn
 * with plain SVG -- no charting/graph-visualization library, per Phase 9's "simple
 * interactive graph is sufficient, do not add a heavy visualization framework"
 * guidance. Positions are computed directly (evenly spaced around a circle), which is
 * enough for this graph's scale (a handful to ~15 relations per threat). */
export function ThreatGraphView({ threatId }: Props) {
  const { data, error } = useThreatGraph(threatId);
  const [hovered, setHovered] = useState<string | null>(null);

  if (error) {
    return <p className="p-4 text-sm text-severity-critical">{error}</p>;
  }

  if (!data) {
    return <div className="h-72 animate-pulse rounded-lg bg-surface-hover" />;
  }

  const n = data.relations.length;
  const positioned = data.relations.map((relation, index) => {
    const angle = (2 * Math.PI * index) / Math.max(n, 1) - Math.PI / 2;
    return {
      relation,
      x: CENTER + RADIUS * Math.cos(angle),
      y: CENTER + RADIUS * Math.sin(angle),
    };
  });

  return (
    <div className="flex flex-col gap-3">
      <svg viewBox={`0 0 ${VIEWBOX_SIZE} ${VIEWBOX_SIZE}`} className="mx-auto w-full max-w-md" role="img" aria-label={`Graph of relationships for ${data.threat.name}`}>
        {positioned.map(({ relation, x, y }) => {
          const key = `${relation.relation}:${relation.target.id}`;
          return (
            <g key={key}>
              <line
                x1={CENTER}
                y1={CENTER}
                x2={x}
                y2={y}
                stroke={hovered === key ? "var(--color-text)" : "var(--color-border-strong)"}
                strokeWidth={hovered === key ? 1.5 : 1}
              />
              <text
                x={(CENTER + x) / 2}
                y={(CENTER + y) / 2 - 4}
                textAnchor="middle"
                className="fill-text-faint"
                style={{ fontSize: 8 }}
              >
                {RELATION_LABEL[relation.relation]}
              </text>
            </g>
          );
        })}

        {positioned.map(({ relation, x, y }) => {
          const key = `${relation.relation}:${relation.target.id}`;
          return (
            <g
              key={key}
              onMouseEnter={() => setHovered(key)}
              onMouseLeave={() => setHovered((current) => (current === key ? null : current))}
              style={{ cursor: "default" }}
            >
              <circle cx={x} cy={y} r={22} fill="var(--color-surface-raised)" stroke={ENTITY_COLOR[relation.target.type]} strokeWidth={2} />
              <text x={x} y={y + 34} textAnchor="middle" className="fill-text" style={{ fontSize: 9 }}>
                {truncate(relation.target.name, 18)}
              </text>
            </g>
          );
        })}

        <circle cx={CENTER} cy={CENTER} r={30} fill="var(--color-accent)" opacity={0.15} stroke="var(--color-accent)" strokeWidth={2} />
        <text x={CENTER} y={CENTER + 4} textAnchor="middle" className="fill-text font-semibold" style={{ fontSize: 10 }}>
          {truncate(data.threat.name, 14)}
        </text>
      </svg>

      <div className="flex flex-wrap justify-center gap-3 text-xs text-text-muted">
        {(Object.keys(ENTITY_COLOR) as EntityType[])
          .filter((type) => type !== "threat")
          .map((type) => (
            <span key={type} className="flex items-center gap-1.5">
              <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: ENTITY_COLOR[type] }} />
              {type}
            </span>
          ))}
      </div>
    </div>
  );
}
