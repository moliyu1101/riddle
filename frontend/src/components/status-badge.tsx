import { cn } from "@/lib/utils";
import {
  statusMeta,
  toneClasses,
  toneDot,
  type StatusDomain,
  type Tone,
} from "@/lib/status";

export function StatusBadge({
  domain,
  value,
  dot = false,
  className,
  title,
}: {
  domain: StatusDomain;
  value: string;
  dot?: boolean;
  className?: string;
  /** 悬停提示。用于把「为什么是这个状态」摆在状态徽章上（如意图的中断原因）。 */
  title?: string;
}) {
  const meta = statusMeta(domain, value);
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border px-2 py-0.5 font-medium text-xs",
        toneClasses[meta.tone],
        className,
      )}
    >
      {dot && (
        <span className={cn("size-1.5 rounded-full", toneDot[meta.tone])} />
      )}
      {meta.label}
    </span>
  );
}

export function ToneDot({ tone }: { tone: Tone }) {
  return <span className={cn("size-2 rounded-full", toneDot[tone])} />;
}
