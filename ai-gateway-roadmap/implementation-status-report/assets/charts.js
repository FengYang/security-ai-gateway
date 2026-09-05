(function() {
  var style = getComputedStyle(document.documentElement);
  var accent = style.getPropertyValue('--accent').trim();
  var accent2 = style.getPropertyValue('--accent2').trim();
  var ink = style.getPropertyValue('--ink').trim();
  var muted = style.getPropertyValue('--muted').trim();
  var rule = style.getPropertyValue('--rule').trim();
  var bg2 = style.getPropertyValue('--bg2').trim();
  var ok = style.getPropertyValue('--ok').trim();
  var part = style.getPropertyValue('--part').trim();
  var todo = style.getPropertyValue('--todo').trim();
  var block = style.getPropertyValue('--block').trim();
  var phase1 = style.getPropertyValue('--phase1').trim();
  var phase2 = style.getPropertyValue('--phase2').trim();
  var phase3 = style.getPropertyValue('--phase3').trim();

  // --- Chart: overall four indicators (bar 0-100) ---
  var overall = echarts.init(document.getElementById('chart-overall'), null, { renderer: 'svg' });
  overall.setOption({
    tooltip: {
      appendToBody: true, animation: false,
      trigger: 'axis', axisPointer: { type: 'shadow' },
      formatter: function(ps) {
        var p = ps[0];
        var base = [{ axisValue: p.name, value: p.value + '%', color: ps[0].data.itemStyle.color }];
        var rows = base.map(function(d) {
          return '<div style="margin:2px 0;">' + d.axisValue + '&nbsp;&nbsp;<b style="color:' + d.color + ';">' + d.value + '</b></div>';
        }).join('');
        return rows;
      }
    },
    grid: { left: 10, right: 20, top: 10, bottom: 10, containLabel: true },
    xAxis: { type: 'value', max: 100, axisLabel: { formatter: '{value}%', color: muted }, splitLine: { lineStyle: { color: rule } } },
    yAxis: {
      type: 'category',
      data: ['真机验收', '路线 2 研究', 'AI 网关能力补齐', '路线 1 代码开发'],
      axisLabel: { color: ink, fontWeight: 600 },
      axisLine: { lineStyle: { color: rule } }, axisTick: { show: false }
    },
    series: [{
      type: 'bar', barWidth: 18, animation: false,
      label: { show: true, position: 'right', formatter: '{c}%', color: ink, fontWeight: 600 },
      data: [
        { value: 0,  itemStyle: { color: block }, name: '真机验收' },
        { value: 5,  itemStyle: { color: todo },  name: '路线 2 研究' },
        { value: 76, itemStyle: { color: part },  name: 'AI 网关能力补齐' },
        { value: 100,itemStyle: { color: ok },    name: '路线 1 代码开发' }
      ]
    }]
  });
  window.addEventListener('resize', function() { overall.resize(); });

  // --- Chart: module structure by layer (stacked bar) ---
  var layers = echarts.init(document.getElementById('chart-layers'), null, { renderer: 'svg' });
  layers.setOption({
    tooltip: {
      appendToBody: true, animation: false,
      trigger: 'axis', axisPointer: { type: 'shadow' }
    },
    legend: { bottom: 0, textStyle: { color: muted }, itemWidth: 14, itemHeight: 10 },
    grid: { left: 10, right: 24, top: 12, bottom: 34, containLabel: true },
    xAxis: {
      type: 'category',
      data: ['密态核心(90%)', 'Tee-infer(75%)', '网关治理(15%)', '控制面(15%)', '部署运维(85%)'],
      axisLabel: { color: ink, fontWeight: 600, interval: 0 }, axisTick: { show: false },
      axisLine: { lineStyle: { color: rule } }
    },
    yAxis: { type: 'value', axisLabel: { color: muted }, splitLine: { lineStyle: { color: rule } } },
    series: [
      { name: '已落地', type: 'bar', stack: 's', barWidth: 34, color: ok,   animation: false, data: [7, 8, 2, 1, 5],
        label: { show: true, color: '#fff', fontWeight: 600 } },
      { name: '部分',   type: 'bar', stack: 's', barWidth: 34, color: part, animation: false, data: [1, 2, 3, 1, 1],
        label: { show: true, color: '#fff', fontWeight: 600 } },
      { name: '未启动', type: 'bar', stack: 's', barWidth: 34, color: todo, animation: false, data: [0, 1, 13, 7, 0],
        label: { show: true, color: '#fff', fontWeight: 600 } }
    ]
  });
  window.addEventListener('resize', function() { layers.resize(); });

  // --- Chart: module total donut (52) ---
  var modules = echarts.init(document.getElementById('chart-modules'), null, { renderer: 'svg' });
  modules.setOption({
    tooltip: { appendToBody: true, animation: false, trigger: 'item',
      formatter: function(p) { return p.name + '：<b>' + p.value + '</b> 个模块（' + p.percent + '%）'; } },
    legend: { bottom: 0, textStyle: { color: muted }, itemWidth: 14, itemHeight: 10 },
    title: {
      text: '~44%', subtext: '总体完成度', left: 'center', top: '35%',
      textStyle: { fontSize: 26, color: ink, fontWeight: 700 },
      subtextStyle: { fontSize: 12, color: muted }
    },
    series: [{
      type: 'pie', radius: ['46%', '66%'], center: ['50%', '42%'], animation: false,
      label: { show: false },
      itemStyle: { borderColor: bg2, borderWidth: 3 },
      color: [ok, part, todo],
      data: [
        { name: '已落地', value: 23 },
        { name: '部分', value: 8 },
        { name: '未启动', value: 21 }
      ]
    }]
  });
  window.addEventListener('resize', function() { modules.resize(); });
})();