# 发布 agent 时的签名步骤（本机离线）

**为什么不在 CI 签**：私钥带密码（一次交互输入），而 CI 没有终端；把它换成无密码密钥会让
「Secret 泄露即可签名」，那是**主动降级**。所以签名留在维护者本机，CI 只构建。

CI 打 tag 后发的是**草稿（draft）**，对 `releases/latest` 不可见，因此未签名的版本**不可能**
变成公开的 —— 这段时间远程升级找不到新版本，是**安全的失败**。

## 三步（打完 tag、等 CI 跑完草稿）

```bash
V=v1.2.3                      # ← 换成你的 tag
mkdir -p /tmp/sign-$V && cd /tmp/sign-$V

# ① 把 CI 构建的产物拉下来
gh release download "$V" --pattern 'monitor-agent-*' -D .

# ② 本机签名（会提示输入私钥密码）
for f in monitor-agent-*; do
  minisign -S -s ~/agent-signing-key.key -m "$f" -t "monitor-agent $V"
done

# ③ 用一个**独立的**工具验一遍（不依赖我们自己的 Rust 代码）
for f in monitor-agent-*; do
  minisign -V -p ~/agent-signing-key.pub -m "$f" -x "$f.minisig" || exit 1
done

# ④ 上传签名，然后把草稿转为正式发布（这一步之后公开页/升级才会看到）
gh release upload "$V" *.minisig
gh release edit "$V" --draft=false
```

## 为什么第 ③ 步要用 `minisign -V` 而不是我们自己的代码

因为那正是**两个独立的通道**：`minisign` 是签名的原始实现，我们 agent 里的
`minisign-verify` 是另一份实现。**两边都过**才说明这份签名既合法、又落进了我们的信任根。
（agent 仓里那 5 条测试已经把「我们这一侧」钉住了：正例必须过、改一个字节必须不过。）

## 信任根在哪儿

- 公钥：`agent-signing-key.pub`（**进仓库、公开**，并**编译进 agent 二进制**）；
- 私钥：只在维护者机器上，**带密码**，从不进仓库、不进 CI；
- 换密钥 = **必须手动升一次 agent**（公钥烧在二进制里）—— 这是这个方案天然的代价。
