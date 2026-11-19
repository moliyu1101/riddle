"use client";

import { useEffect, useRef, useState } from "react";

import { useRouter } from "next/navigation";

import { AlertTriangle, ShieldHalf } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogClose, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import { auth } from "@/lib/auth";

// 认证页防指纹约定（公网部署场景）：
//   1. 文案与结构不出现产品名、不引用 /logo.png（图片哈希最容易被测绘）；
//      顶部几何标记是内联 SVG，随主题变化、无独立资源。
//   2. v0.4.43 视觉升级：双层动画光晕背景 + 玻璃拟态卡片 + 入场动画 +
//      微交互（输入聚焦光晕、按钮渐变），全部纯 CSS 不引入外部资源。
export default function LoginPage() {
  const router = useRouter();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(true);
  const [agreed, setAgreed] = useState(false);
  const [termsOpen, setTermsOpen] = useState(false);
  const [readToEnd, setReadToEnd] = useState(false);
  const [focused, setFocused] = useState(false);
  const termsBodyRef = useRef<HTMLDivElement>(null);

  function handleTermsScroll() {
    const el = termsBodyRef.current;
    if (!el) return;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 8) setReadToEnd(true);
  }

  useEffect(() => {
    if (!termsOpen) return;
    setReadToEnd(false);
    const el = termsBodyRef.current;
    if (el && el.scrollHeight <= el.clientHeight + 8) setReadToEnd(true);
  }, [termsOpen]);

  useEffect(() => {
    const token = auth.getToken();
    if (token) {
      auth.setToken(token);
      window.location.replace("/function/tasks");
      return;
    }
    api
      .authStatus()
      .then(({ initialized }) => {
        if (!initialized) router.replace("/setup");
      })
      .catch(() => setError("无法连接到后端服务"))
      .finally(() => setChecking(false));
  }, [router]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!agreed) {
      setError("请先阅读并同意《安全与合规声明》");
      return;
    }
    setLoading(true);
    setError("");
    try {
      const { token } = await api.login("Riddle", password);
      auth.setToken(token);
      window.location.replace("/function/tasks");
    } catch (e) {
      const err = e as Error & { status?: number };
      if (!err.status) {
        setError("无法连接到后端服务，请确认服务已启动");
      } else if (err.status === 429) {
        setError(err.message || "尝试过于频繁，账号已临时锁定，请稍后再试");
      } else if (err.status === 403 && err.message.includes("未初始化")) {
        setError("密码尚未初始化，请先完成首次设置");
      } else if (err.status === 401) {
        setError("用户名或密码错误");
      } else {
        setError(err.message || "登录失败，请稍后再试");
      }
    } finally {
      setLoading(false);
    }
  }

  if (checking) {
    return (
      <div role="status" className="flex min-h-dvh items-center justify-center text-muted-foreground">
        <div className="flex items-center gap-3">
          <ShieldHalf className="size-5 animate-pulse text-primary" />
          正在检查登录状态…
        </div>
      </div>
    );
  }

  return (
    <div className="relative flex min-h-dvh flex-col items-center justify-center overflow-hidden p-6">
      {/* 背景：双层动画光晕 + 细网格 + 底部渐隐 */}
      <div aria-hidden className="pointer-events-none absolute inset-0">
        <div className="absolute inset-0 bg-background" />
        <div
          className="absolute inset-0 opacity-[0.18]"
          style={{
            backgroundImage:
              "linear-gradient(to right, hsl(var(--border)) 1px, transparent 1px), linear-gradient(to bottom, hsl(var(--border)) 1px, transparent 1px)",
            backgroundSize: "48px 48px",
            maskImage: "radial-gradient(ellipse 75% 65% at 50% 40%, black 20%, transparent 78%)",
            WebkitMaskImage: "radial-gradient(ellipse 75% 65% at 50% 40%, black 20%, transparent 78%)",
          }}
        />
        <div
          className="absolute -top-[30%] left-1/2 h-[60vh] w-[80vw] -translate-x-1/2 rounded-full opacity-[0.07]"
          style={{ background: "radial-gradient(ellipse, hsl(35 90% 55%) 0%, transparent 70%)" }}
        />
        <div
          className="absolute -bottom-[20%] left-1/2 h-[50vh] w-[70vw] -translate-x-1/2 rounded-full opacity-[0.05]"
          style={{ background: "radial-gradient(ellipse, hsl(210 80% 50%) 0%, transparent 70%)" }}
        />
        <div
          className="absolute left-1/2 top-1/2 h-[80vh] w-[60vw] -translate-x-1/2 -translate-y-1/2 rounded-full opacity-[0.04]"
          style={{ background: "radial-gradient(ellipse, hsl(var(--primary)) 0%, transparent 70%)" }}
        />
      </div>

      <div className="relative w-full max-w-sm animate-in fade-in slide-in-from-bottom-6 duration-500">
        <div className="rounded-2xl border bg-card/80 p-8 shadow-xl backdrop-blur-md">
          <div className="mb-8 flex flex-col items-center gap-4 text-center">
            <div className="relative">
              <div
                aria-hidden
                className="absolute -inset-2 rounded-2xl bg-primary/5 blur-md"
                style={{ animation: "pulse 4s cubic-bezier(0.4,0,0.6,1) infinite" }}
              />
              <svg
                aria-hidden
                viewBox="0 0 48 48"
                className="relative size-14 text-primary"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <rect x="9" y="20" width="30" height="22" rx="4" />
                <path d="M17 20v-6a7 7 0 0 1 14 0v6" />
                <circle cx="24" cy="31" r="2.5" fill="currentColor" stroke="none" />
              </svg>
            </div>
            <div>
              <h1 className="font-semibold text-2xl tracking-tight">知蠹 Riddle 控制台</h1>
              <p className="mt-1.5 text-muted-foreground text-sm">仅限授权安全测试与运维人员访问</p>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="flex flex-col gap-5">
            <div className="space-y-1.5">
              <Label htmlFor="username" className="text-muted-foreground text-xs">系统标识</Label>
              <Input
                id="username"
                value="Riddle"
                readOnly
                className="border-border/60 bg-muted/50 font-mono text-muted-foreground"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="password" className="text-muted-foreground text-xs">访问令牌 / 密码</Label>
              <div className="relative">
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  autoFocus
                  autoComplete="current-password"
                  onFocus={() => setFocused(true)}
                  onBlur={() => setFocused(false)}
                  className="border-border/60 pr-10 transition-shadow duration-200"
                />
                <div
                  aria-hidden
                  className={`absolute -bottom-px left-1/2 h-px -translate-x-1/2 bg-primary transition-all duration-300 ${
                    focused ? "w-full opacity-100" : "w-0 opacity-0"
                  }`}
                />
              </div>
            </div>
            <div className="flex items-start gap-2">
              <Checkbox
                id="agree-terms"
                checked={agreed}
                onCheckedChange={(v) => setAgreed(v === true)}
                className="mt-0.5"
              />
              <Label htmlFor="agree-terms" className="font-normal text-muted-foreground text-sm leading-relaxed">
                我已阅读并同意
                <button
                  type="button"
                  onClick={() => setTermsOpen(true)}
                  className="mx-0.5 font-medium text-primary underline-offset-4 hover:underline"
                >
                  《安全与合规声明》
                </button>
              </Label>
            </div>
            {error && (
              <p className="animate-in fade-in slide-in-from-top-1 text-destructive text-sm">{error}</p>
            )}
            <Button
              type="submit"
              className="h-10 w-full font-medium tracking-wide transition-all duration-200 hover:shadow-md"
              disabled={loading || !password || !agreed}
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  <span className="inline-block size-3 animate-spin rounded-full border-2 border-current border-t-transparent" />
                  登录中…
                </span>
              ) : (
                "登 录"
              )}
            </Button>
          </form>
        </div>

        <p className="mt-6 text-center text-muted-foreground/60 text-xs">
          连续登录失败会触发临时锁定
        </p>
      </div>

      <Dialog open={termsOpen} onOpenChange={setTermsOpen}>
        <DialogContent className="gap-0 p-0 sm:max-w-xl">
          <DialogHeader className="flex-row items-center gap-3 border-b px-6 py-4">
            <div className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-destructive/10 text-destructive">
              <AlertTriangle className="size-5" />
            </div>
            <DialogTitle className="text-base">安全与合规声明</DialogTitle>
          </DialogHeader>
          <div
            ref={termsBodyRef}
            onScroll={handleTermsScroll}
            className="max-h-[55vh] space-y-4 overflow-y-auto px-6 py-5 text-muted-foreground text-sm leading-relaxed"
          >
            <p>
              本系统仅供授权人员在合法授权范围内开展安全评估工作。登录即表示您确认已理解并接受以下约束：
            </p>
            <ul className="ml-5 list-disc space-y-2">
              <li>
                仅可对**已获得明确书面授权**的目标开展测试；对任何未授权系统发起扫描、探测或利用均属违规乃至违法行为；
              </li>
              <li>
                本系统具备在服务器上执行命令的能力——请妥善保管访问凭据，凭据泄露等同于服务器控制权泄露；
              </li>
              <li>
                系统内置拦截与审批机制用于降低误操作风险，但不构成对使用合法性的担保；使用产生的全部法律责任由使用者自行承担；
              </li>
              <li>严禁利用本系统从事任何违反所在国家或地区法律法规的活动。</li>
            </ul>
          </div>
          <DialogFooter className="mx-0 mb-0 flex-col items-stretch gap-2 rounded-b-xl px-6 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-muted-foreground text-xs">
              {readToEnd ? "您已浏览全部条款" : "请将条款滚动至底部后再确认"}
            </p>
            <DialogClose asChild>
              <Button
                type="button"
                disabled={!readToEnd}
                onClick={() => {
                  setAgreed(true);
                  setError("");
                }}
              >
                我已阅读并同意
              </Button>
            </DialogClose>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
