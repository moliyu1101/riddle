import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

// 文档标题与描述是公网未鉴权即可抓到的指纹面（根路径 / 404 页都会带）。
// 保持中性，产品名只出现在登录后界面（可见即已通过鉴权）。
export const APP_CONFIG = {
  name: "知蠹 Riddle",
  version: packageJson.version,
  copyright: `© ${currentYear}, 知蠹 Riddle.`,
  meta: {
    title: "知蠹 Riddle · 自主安全渗透与漏洞挖掘平台",
    description: "自主安全渗透、AI + 人工漏洞挖掘闭环与融合治理平台",
  },
};
