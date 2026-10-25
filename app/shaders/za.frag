#version 450
// 宝可梦 Z-A 宿主自用：渐变着色，用来确认渲染通路真的在出图。
layout(location = 0) in vec2 vUV;
layout(location = 0) out vec4 outColor;

void main()
{
    outColor = vec4(vUV.x, vUV.y, 0.55, 1.0);
}
