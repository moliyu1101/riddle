"""JS 业务状态机信号提取：多步流/审批/支付/预约等前端信号识别。"""
from __future__ import annotations

import unittest

from app.tools.executor import ToolExecutor
from app.tools.js_analyzer import analyze_javascript


class JsStateMachineTests(unittest.TestCase):
    def test_multi_step_wizard_detected(self):
        js = """
        const currentStep = ref(0);
        const stepToken = '';
        function nextStep() { currentStep.value++; }
        function goToStep(n) { currentStep.value = n; }
        const flowId = 'xxx';
        if (status === '待审批') { updateStatus('已通过'); }
        """
        r = analyze_javascript(js)
        sm = r["state_machines"]
        self.assertTrue(sm, "应识别出状态机信号")
        self.assertEqual(sm[0]["label"], "业务状态机/多步流信号")
        sig = sm[0]["signals"]
        self.assertIn("step_vars", sig)
        self.assertIn("transition_fns", sig)
        self.assertIn("flow_tokens", sig)
        self.assertIn("status_values", sig)
        self.assertIn("state_machine", [f["kind"] for f in r["findings"]])
        self.assertTrue(any(c["kind"] == "business_state_machine" for c in r["chains"]))

    def test_approval_flow_detected(self):
        js = """
        const processInstanceId = 'pi_123';
        function updateStatus(s) { this.status = s; }
        const status = '待审批';
        function approve() { updateStatus('已通过'); }
        """
        r = analyze_javascript(js)
        sm = r["state_machines"]
        self.assertTrue(sm)
        sig = sm[0]["signals"]
        self.assertIn("flow_tokens", sig)
        self.assertIn("status_values", sig)

    def test_no_signal_returns_empty(self):
        js = "const a = 1; function hello() { return 'world'; }"
        r = analyze_javascript(js)
        self.assertEqual(r["state_machines"], [])
        self.assertNotIn("state_machine", [f["kind"] for f in r["findings"]])

    def test_weak_signal_ignored(self):
        # 只有裸 step，无其他信号 → 不产出（低于最少信号数）
        js = "const step = 0; for (let i = 0; i < step; i++) {}"
        r = analyze_javascript(js)
        self.assertEqual(r["state_machines"], [])

    def test_payment_flow_detected(self):
        js = """
        const orderToken = 'ot_1';
        const currentStep = 2;
        if (orderStatus === '未支付') {
          setStatus('已支付');
          nextStep();
        }
        """
        r = analyze_javascript(js)
        sm = r["state_machines"]
        self.assertTrue(sm)
        sig = sm[0]["signals"]
        self.assertIn("status_values", sig)
        self.assertTrue(any("已支付" in v for v in sig["status_values"]))

    def test_state_machine_map_has_probes(self):
        js = """
        const currentStep = ref(0);
        const stepToken = '';
        function nextStep() {}
        function updateStatus(s) {}
        const status = '待审批';
        """
        r = analyze_javascript(js)
        sm = r["state_machines"][0]
        self.assertTrue(sm["probes"])
        self.assertTrue(any("步骤跳过" in p for p in sm["probes"]))
        self.assertTrue(any("状态篡改" in p for p in sm["probes"]))

    def test_executor_passthrough_state_machines(self):
        ex = ToolExecutor(target="https://example.edu.cn/")
        js = """
        const currentStep = ref(0);
        const stepToken = '';
        function nextStep() {}
        function updateStatus(s) {}
        const status = '待审批';
        """
        r = ex.analyze_javascript(text=js)
        self.assertTrue(r["ok"])
        self.assertTrue(r["state_machines"])
        self.assertTrue(any("状态篡改" in p for p in r["state_machines"][0]["probes"]))
        self.assertIn("业务状态机", r["guidance"])


if __name__ == "__main__":
    unittest.main()
