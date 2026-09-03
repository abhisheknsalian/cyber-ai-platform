import { useMemo, useState } from "react";

import { useThreatGraph } from "../../hooks/useThreatGraph";
import type { EntityType, RelationSummary, RelationType } from "../../types/intelligence";

const VIEWBOX_SIZE = 400;
const CENTER = VIEWBOX_SIZE / 2;
const RADIUS = 150;

// Matches the severity/accent CSS custom properties already defined in
// frontend/src/index.css -- no new colors introduced, just reused with a different
// meaning here (entity type instead of severity).
const ENTITY_COLOR: Record<EntityType, string> = {
  threat: "var(--color-accent)",
  technique: "var(--color-malicious)",
  indicator: "var(--color-warning)",
  mitigation: "var(--color-benign)",
  source: "var(--color-text-muted)",
};

const ENTITY_LABEL: Record<EntityType, string> = {
  threat: "Threat",
  technique: "Technique",
  indicator: "Indicator",
  mitigation: "Mitigation",
  source: "Source",
};

const RELATION_LABEL: Record<RelationType, string> = {
  USES: "uses",
  HAS_INDICATOR: "has indicator",
  MITIGATED_BY: "mitigated by",
  SUPPORTED_BY: "sourced from",
};

function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function relationKey(relation: RelationSummary): string {
  return `${relation.relation}:${relation.target.id}`;
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
  const [selected, setSelected] = useState<string | null>(null);

  const activeKey = hovered ?? selected;

  const positioned = useMemo(() => {
    if (!data) return [];
    const n = data.relations.length;
    return data.relations.map((relation, index) => {
      const angle = (2 * Math.PI * index) / Math.max(n, 1) - Math.PI / 2;
      return {
        relation,
        x: CENTER + RADIUS * Math.cos(angle),
        y: CENTER + RADIUS * Math.sin(angle),
      };
    });
  }, [data]);

  if (error) {
    return (
      <p className="rounded-md border border-malicious/30 bg-malicious/5 p-4 text-sm text-malicious-strong">{error}</p>
    );
  }

  if (!data) {
    return <div className="h-80 animate-pulse rounded-lg bg-surface-hover" />;
  }

  const selectedRelation = positioned.find(({ relation }) => relationKey(relation) === activeKey)?.relation ?? null;

  return (
    <div className="flex flex-col gap-4 lg:flex-row">
      <svg
        viewBox={`0 0 ${VIEWBOX_SIZE} ${VIEWBOX_SIZE}`}
        className="mx-auto w-full max-w-md shrink-0"
        role="img"
        aria-label={`Graph of relationships for ${data.threat.name}`}
      >
        {positioned.map(({ relation, x, y }) => {
          const key = relationKey(relation);
          const active = activeKey === key;
          return (
            <line
              key={key}
              x1={CENTER}
              y1={CENTER}
              x2={x}
              y2={y}
              stroke={active ? ENTITY_COLOR[relation.target.type] : "var(--color-border-strong)"}
              strokeWidth={active ? 2 : 1}
              className="transition-all duration-150"
            />
          );
        })}

        {positioned.map(({ relation, x, y }) => {
          const key = relationKey(relation);
          const active = activeKey === key;
          return (
            <text
              key={`label-${key}`}
              x={(CENTER + x) / 2}
              y={(CENTER + y) / 2 - 6}
              textAnchor="middle"
              className={active ? "fill-text font-semibold" : "fill-text-faint"}
              style={{ fontSize: 9 }}
            >
              {RELATION_LABEL[relation.relation]}
            </text>
          );
        })}

        {positioned.map(({ relation, x, y }) => {
          const key = relationKey(relation);
          const active = activeKey === key;
          return (
            <g
              key={key}
              onMouseEnter={() => setHovered(key)}
              onMouseLeave={() => setHovered((current) => (current === key ? null : current))}
              onClick={() => setSelected((current) => (current === key ? null : key))}
              role="button"
              tabIndex={0}
              aria-label={`${relation.target.name} (${ENTITY_LABEL[relation.target.type]})`}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  setSelected((current) => (current === key ? null : key));
                }
              }}
              style={{ cursor: "pointer" }}
              className="outline-none"
            >
              <circle
                cx={x}
                cy={y}
                r={active ? 26 : 22}
                fill="var(--color-surface-raised)"
                stroke={ENTITY_COLOR[relation.target.type]}
                strokeWidth={selected === key ? 3 : 2}
                className="transition-all duration-150"
              />
              <text x={x} y={y + 38} textAnchor="middle" className="fill-text" style={{ fontSize: 10 }}>
                {truncate(relation.target.name, 18)}
              </text>
            </g>
          );
        })}

        <circle
          cx={CENTER}
          cy={CENTER}
          r={32}
          fill="var(--color-accent)"
          opacity={0.15}
          stroke="var(--color-accent)"
          strokeWidth={2}
        />
        <text x={CENTER} y={CENTER + 4} textAnchor="middle" className="fill-text font-semibold" style={{ fontSize: 11 }}>
          {truncate(data.threat.name, 14)}
        </text>
      </svg>

      <div className="flex min-w-0 flex-1 flex-col gap-3">
        <div className="rounded-md border border-border bg-surface px-3 py-2.5">
          {selectedRelation ? (
            <div>
              <div className="flex items-center justify-between gap-2">
                <span
                  className="rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide"
                  style={{
                    color: ENTITY_COLOR[selectedRelation.target.type],
                    borderColor: ENTITY_COLOR[selectedRelation.target.type],
                  }}
                >
                  {ENTITY_LABEL[selectedRelation.target.type]}
                </span>
                <span className="font-mono text-[11px] text-text-faint">
                  {RELATION_LABEL[selectedRelation.relation]}
                </span>
              </div>
              <p className="mt-1.5 text-sm font-medium text-text">{selectedRelation.target.name}</p>
              {selectedRelation.reference ? (
                <p className="mt-1 text-xs text-text-muted">{selectedRelation.reference}</p>
              ) : null}
            </div>
          ) : (
            <p className="text-xs text-text-faint">
              Hover or select a node to see its relationship to {data.threat.name}.
            </p>
          )}
        </div>

        <div className="flex flex-wrap gap-x-4 gap-y-2 text-xs text-text-muted">
          {(Object.keys(ENTITY_COLOR) as EntityType[])
            .filter((type) => type !== "threat")
            .map((type) => (
              <span key={type} className="flex items-center gap-1.5">
                <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: ENTITY_COLOR[type] }} />
                {ENTITY_LABEL[type]}
              </span>
            ))}
        </div>

        {data.relations.length === 0 ? (
          <p className="text-sm text-text-faint">No graph relationships recorded for this threat.</p>
        ) : null}
      </div>
    </div>
  );
}
