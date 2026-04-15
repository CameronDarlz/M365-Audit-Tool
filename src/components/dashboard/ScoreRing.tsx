import { useEffect, useRef } from 'react';
import { gradeColor, scoreToGrade } from '../../lib/utils';
import type { CategoryScore } from '../../types/audit';

interface ScoreRingProps {
  score: number;
  size?: number;
  strokeWidth?: number;
  label?: string;
  sublabel?: string;
  grade?: CategoryScore['grade'];
  animate?: boolean;
}

export function ScoreRing({
  score,
  size = 120,
  strokeWidth = 10,
  label,
  sublabel,
  grade,
  animate = true,
}: ScoreRingProps) {
  const circleRef = useRef<SVGCircleElement>(null);
  const resolvedGrade = grade ?? scoreToGrade(score);
  const color = gradeColor(resolvedGrade);

  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const targetOffset = circumference * (1 - score / 100);

  useEffect(() => {
    const el = circleRef.current;
    if (!el) return;

    if (animate) {
      el.style.strokeDashoffset = String(circumference);
      el.style.transition = 'none';
      void el.getBoundingClientRect(); // force reflow
      el.style.transition = 'stroke-dashoffset 1.2s cubic-bezier(0.4,0,0.2,1)';
      el.style.strokeDashoffset = String(targetOffset);
    } else {
      el.style.strokeDashoffset = String(targetOffset);
    }
  }, [score, animate, circumference, targetOffset]);

  const gradeLabel = resolvedGrade.charAt(0).toUpperCase() + resolvedGrade.slice(1);

  return (
    <div className="flex flex-col items-center gap-1">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
          {/* Track */}
          <circle
            cx={size / 2} cy={size / 2} r={radius}
            fill="none"
            stroke="#1e3a5f"
            strokeWidth={strokeWidth}
          />
          {/* Fill */}
          <circle
            ref={circleRef}
            cx={size / 2} cy={size / 2} r={radius}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={circumference}
          />
        </svg>
        {/* Centre text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono font-bold leading-none" style={{
            fontSize: size >= 120 ? 28 : size >= 80 ? 20 : 16,
            color,
          }}>
            {score}
          </span>
          <span className="text-[10px] font-medium uppercase tracking-wider mt-0.5" style={{ color }}>
            {gradeLabel}
          </span>
        </div>
      </div>
      {label && (
        <span className="text-xs font-medium text-text text-center">{label}</span>
      )}
      {sublabel && (
        <span className="text-[10px] text-muted text-center">{sublabel}</span>
      )}
    </div>
  );
}
