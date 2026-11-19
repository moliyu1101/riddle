"use client";

import Link from "next/link";

import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <div className="flex h-dvh flex-col items-center justify-center space-y-2 text-center">
      <h1 className="font-semibold text-2xl">页面不存在</h1>
      <p className="text-muted-foreground">你要找的页面不存在或已被移动。</p>
      <Link prefetch={false} replace href="/function/tasks">
        <Button variant="outline">回到工作台</Button>
      </Link>
    </div>
  );
}
