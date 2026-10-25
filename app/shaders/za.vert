#version 450
// 宝可梦 Z-A 宿主自用：全屏三角形（无顶点缓冲，靠 gl_VertexIndex 生成）。
// 之后接入游戏时，这条通路会换成「控制段哈希 → 预翻好的 SPIR-V」运行时查表。
layout(location = 0) out vec2 vUV;

void main()
{
    vec2 p = vec2(float((gl_VertexIndex << 1) & 2), float(gl_VertexIndex & 2));
    vUV = p;
    gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);
}
