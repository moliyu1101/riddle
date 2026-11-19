"use client";

// ZoomableImageDialog（v0.4.48）：现场证据图片预览支持滚轮缩放 + 拖拽平移 +
// 双击还原 + 重置按钮，替代静态 img 展示——报告阅读时需要放大细节（URL/参数/
// 响应特征），静态图看不清导致误判。

import * as React from "react";

import { Maximize2Icon } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface ZoomState {
  scale: number;
  x: number;
  y: number;
}

const MIN_SCALE = 0.5;
const MAX_SCALE = 8;

export function ZoomableImageDialog({
  open,
  onClose,
  src,
  title,
  description,
  downloadUrl,
  footer,
}: {
  open: boolean;
  onClose: () => void;
  src: string;
  title: string;
  description?: string;
  downloadUrl?: string;
  /** 额外控件行（如文档分页的上一页/下一页），渲染在信息栏下方；src 变化（翻页）时缩放状态自动重置。 */
  footer?: React.ReactNode;
}) {
  const [zoom, setZoom] = React.useState<ZoomState>({ scale: 1, x: 0, y: 0 });
  const dragRef = React.useRef<{ startX: number; startY: number; baseX: number; baseY: number } | null>(null);
  const [dragging, setDragging] = React.useState(false);

  // 打开时重置
  React.useEffect(() => {
    if (open) setZoom({ scale: 1, x: 0, y: 0 });
  }, [open, src]);

  const handleWheel = React.useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    setZoom((z) => {
      const factor = e.deltaY < 0 ? 1.15 : 0.87;
      const next = Math.min(MAX_SCALE, Math.max(MIN_SCALE, z.scale * factor));
      return { ...z, scale: next };
    });
  }, []);

  const handleDoubleClick = React.useCallback(() => {
    setZoom((z) => (z.scale > 1 ? { scale: 1, x: 0, y: 0 } : { scale: 3, x: 0, y: 0 }));
  }, []);

  const handleMouseDown = React.useCallback(
    (e: React.MouseEvent) => {
      if (zoom.scale <= 1) return;
      dragRef.current = { startX: e.clientX, startY: e.clientY, baseX: zoom.x, baseY: zoom.y };
      setDragging(true);
    },
    [zoom.scale, zoom.x, zoom.y],
  );

  const handleMouseMove = React.useCallback(
    (e: React.MouseEvent) => {
      const d = dragRef.current;
      if (!d || !dragging) return;
      setZoom((z) => ({ ...z, x: d.baseX + (e.clientX - d.startX), y: d.baseY + (e.clientY - d.startY) }));
    },
    [dragging],
  );

  const handleMouseUp = React.useCallback(() => {
    dragRef.current = null;
    setDragging(false);
  }, []);

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="flex max-h-[90dvh] flex-col sm:max-w-5xl">
        <DialogHeader>
          <DialogTitle className="break-all pr-6 text-base">{title}</DialogTitle>
          {description ? <DialogDescription className="break-all">{description}</DialogDescription> : null}
        </DialogHeader>
        <div
          className="relative flex-1 overflow-hidden rounded-md border bg-black/5 select-none"
          onWheel={handleWheel}
          onDoubleClick={handleDoubleClick}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          style={{ cursor: zoom.scale > 1 ? (dragging ? "grabbing" : "grab") : "default", minHeight: "300px" }}
        >
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src={src}
            alt={title}
            draggable={false}
            className="mx-auto max-h-[62vh] w-auto max-w-full origin-center object-contain transition-transform duration-100"
            style={{
              transform: `translate(${zoom.x}px, ${zoom.y}px) scale(${zoom.scale})`,
            }}
          />
        </div>
        <div className="flex flex-wrap items-center justify-between gap-2 text-muted-foreground text-xs">
          <span className="flex items-center gap-1">
            滚轮缩放 · 拖拽平移 · 双击还原/放大
            {zoom.scale > 1 ? ` · ${Math.round(zoom.scale * 100)}%` : ""}
          </span>
          <div className="flex items-center gap-1">
            <Button size="sm" variant="ghost" onClick={() => setZoom({ scale: 1, x: 0, y: 0 })}>
              <Maximize2Icon className="size-3.5" /> 还原
            </Button>
            {downloadUrl ? (
              <Button size="sm" variant="outline" asChild>
                <a href={downloadUrl}>下载原件</a>
              </Button>
            ) : null}
          </div>
        </div>
        {footer}
      </DialogContent>
    </Dialog>
  );
}
