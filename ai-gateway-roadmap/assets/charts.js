// ai-gateway-roadmap — charts.js
(function() {
  var style = getComputedStyle(document.documentElement);
  var accent  = style.getPropertyValue('--accent').trim();
  var accent2 = style.getPropertyValue('--accent2').trim();
  var ink     = style.getPropertyValue('--ink').trim();
  var muted   = style.getPropertyValue('--muted').trim();
  var rule    = style.getPropertyValue('--rule').trim();
  var bg2     = style.getPropertyValue('--bg2').trim();
  var phase1  = style.getPropertyValue('--phase1').trim() || '#2a7d6f';
  var phase2  = style.getPropertyValue('--phase2').trim() || '#c06a14';
  var phase3  = style.getPropertyValue('--phase3').trim() || '#4a4e9e';

  var DIMS = ['D1 路由编排','D2 内容安全','D3 密态/可信','D4 租户治理','D5 可观测性能','D6 生态成熟','D7 安全整合'];

  // 当前 / P1 / P2 / P3 各维度得分
  var SCORES = {
    '当前':  [2, 3, 5, 2, 3, 2, 5],
    'Phase 1': [4, 3, 5, 4, 4, 3, 5],
    'Phase 2': [4, 5, 5, 4, 4, 3, 5],
    'Phase 3': [5, 5, 5, 5, 5, 4, 5]
  };

  // --- 06-A 雷达图 ---
  var radarEl = document.getElementById('chart-radar');
  if (radarEl) {
    var radar = echarts.init(radarEl, null, {renderer:'svg'});
    var series = Object.keys(SCORES).map(function(name, i){
      var colors = [muted, phase1, phase2, phase3];
      var c = colors[i];
      return {
        name: name,
        type: 'radar',
        data: [{ value: SCORES[name], name: name }],
        symbol: 'circle',
        symbolSize: 5,
        lineStyle: { color: c, width: 2 },
        itemStyle: { color: c },
        areaStyle: { color: c + '22' }
      };
    });
    radar.setOption({
      animation:false,
      tooltip:{trigger:'item', appendToBody:true},
      legend:{bottom:0, textStyle:{color:muted, fontSize:12}, itemWidth:14, itemHeight:8},
      radar:{
        indicator: DIMS.map(function(d){ return { name:d, max:5 }; }),
        radius: '68%',
        center: ['50%','48%'],
        axisName:{ color:ink, fontSize:12 },
        splitArea:{ areaStyle:{ color:[bg2, 'rgba(0,0,0,.025)'] } },
        axisLine:{ lineStyle:{color:rule} },
        splitLine:{ lineStyle:{color:rule} }
      },
      series: series
    });
    window.addEventListener('resize', function(){ radar.resize(); });
  }

  // --- 06-B 堆叠横向柱：当前→P3 各维度增长 ---
  var barEl = document.getElementById('chart-bar');
  if (barEl) {
    var bar = echarts.init(barEl, null, {renderer:'svg'});
    var phases = ['当前','Phase 1','Phase 2','Phase 3'];
    var colors = [muted, phase1, phase2, phase3];
    // 将 SCORES 转换成按维度堆叠: 对每个 phase，画出它的"增加值"
    // 简化: 直接四个 series，每个是该 phase 的最终值（作为普通 bar，不 stack 更直观比较绝对值）
    var series = phases.map(function(p, i){
      return {
        name: p, type: 'bar',
        data: SCORES[p],
        itemStyle:{ color: colors[i], borderRadius:[0,0,0,0] },
        barWidth: 14
      };
    });
    bar.setOption({
      animation:false,
      tooltip:{trigger:'axis', appendToBody:true, axisPointer:{type:'shadow'}},
      legend:{bottom:0, textStyle:{color:muted, fontSize:12}, itemWidth:14, itemHeight:8},
      grid:{top:16, right:40, bottom:50, left:100},
      xAxis:{ type:'value', min:0, max:5,
        axisLine:{show:false}, axisTick:{show:false},
        splitLine:{lineStyle:{color:rule}},
        axisLabel:{color:muted, formatter:'{value}'}
      },
      yAxis:{ type:'category', data:DIMS,
        axisLine:{show:false}, axisTick:{show:false},
        axisLabel:{color:ink, fontSize:12}
      },
      series: series
    });
    window.addEventListener('resize', function(){ bar.resize(); });
  }

  // --- 06-C 散点图：接入维度(D1均值) vs 密态(D3) ---
  // 我们 + 代表性竞品的 D1/D3
  // 竞品数值以《GA-技术架构方案.md》§10「竞争力分析」矩阵为唯一源（2026-11-05 阶段 A 裁定 MD 权威）。
  // 本图为可视化快照：§10 更新时须同步此处，不得据此反向修改 §10，亦不得另立第二份评分。
  var scatterEl = document.getElementById('chart-scatter');
  if (scatterEl) {
    var scatter = echarts.init(scatterEl, null, {renderer:'svg'});
    // 点：[D1, D3, 名称, 类别]
    var points = [
      // 我们自身（四个阶段）
      { name:'我们·当前',  d1: 2, d3: 5, cat:'OTP-Mask' },
      { name:'我们·Phase 1', d1:4, d3:5, cat:'OTP-Mask' },
      { name:'我们·Phase 2', d1:4, d3:5, cat:'OTP-Mask' },
      { name:'我们·Phase 3', d1:5, d3:5, cat:'OTP-Mask' },
      // 开源通用网关
      { name:'Higress', d1:5, d3:1, cat:'开源通用' },
      { name:'Envoy AI Gateway', d1:4, d3:1, cat:'开源通用' },
      { name:'Kong AI Gateway', d1:4, d3:1, cat:'开源通用' },
      { name:'APISIX', d1:4, d3:1, cat:'开源通用' },
      // Lite 网关
      { name:'LiteLLM', d1:5, d3:0, cat:'Lite 网关' },
      { name:'Portkey', d1:4, d3:0, cat:'Lite 网关' },
      // 云厂商
      { name:'Cloudflare', d1:4, d3:1, cat:'云平台' },
      { name:'Azure APIM+Foundry', d1:4, d3:2, cat:'云平台' },
      { name:'AWS Bedrock', d1:3, d3:2, cat:'云平台' },
      { name:'阿里云百炼 C-MaaS', d1:4, d3:4, cat:'云平台' },
      { name:'NVIDIA NIM', d1:3, d3:1, cat:'云平台' }
    ];

    var catColor = {
      'OTP-Mask':   { color: accent,  size: 22, symbol: 'diamond' },
      '开源通用':     { color: '#7a8c99', size: 12, symbol: 'circle' },
      'Lite 网关':    { color: '#a07233', size: 12, symbol: 'circle' },
      '云平台':       { color: '#4a5f7a', size: 12, symbol: 'circle' }
    };

    var dataset = {};
    points.forEach(function(p){
      if (!dataset[p.cat]) dataset[p.cat] = [];
      dataset[p.cat].push({ value:[p.d1, p.d3], name:p.name });
    });

    var series = Object.keys(dataset).map(function(cat){
      var cfg = catColor[cat];
      return {
        name: cat, type: 'scatter',
        data: dataset[cat],
        symbolSize: cfg.size,
        symbol: cfg.symbol,
        itemStyle: { color: cfg.color + (cat==='OTP-Mask'?'':'cc') },
        label:{
          show: cat==='OTP-Mask',
          formatter: function(p){ return p.data.name; },
          position: 'right', color: ink, fontSize: 11, fontWeight:600
        },
        emphasis: {
          label:{ show:true, formatter:function(p){return p.data.name;}, position:'top', color:ink, fontSize:11 }
        }
      };
    });

    scatter.setOption({
      animation:false,
      tooltip:{ trigger:'item', appendToBody:true,
        formatter: function(p){
          return '<b>'+p.data.name+'</b><br>接入维度（D1）：'+p.value[0]+' 分<br>密态可信（D3）：'+p.value[1]+' 分';
        }
      },
      legend:{bottom:0, textStyle:{color:muted, fontSize:12}, itemWidth:12, itemHeight:12},
      grid:{top:20, right:40, bottom:60, left:60},
      xAxis:{
        name:'接入能力（D1）',
        nameTextStyle:{color:muted, fontSize:12, padding:[8,0,0,0]},
        type:'value', min:0, max:5,
        axisLine:{lineStyle:{color:rule}},
        axisLabel:{color:muted},
        splitLine:{lineStyle:{color:rule}}
      },
      yAxis:{
        name:'密态可信（D3）',
        nameTextStyle:{color:muted, fontSize:12, padding:[0,0,8,0]},
        type:'value', min:0, max:5,
        axisLine:{lineStyle:{color:rule}},
        axisLabel:{color:muted},
        splitLine:{lineStyle:{color:rule}}
      },
      series: series
    });
    window.addEventListener('resize', function(){ scatter.resize(); });
  }
})();