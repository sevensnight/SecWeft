import { BarChart } from 'echarts/charts';
import { GridComponent, TooltipComponent } from 'echarts/components';
import * as echarts from 'echarts/core';
import { CanvasRenderer } from 'echarts/renderers';
import { useEffect, useRef } from 'react';

import { cnLabel } from '../../../i18n/formatters';

echarts.use([BarChart, GridComponent, TooltipComponent, CanvasRenderer]);

export function TaskStatusChart({ values }: { values: Record<string, number> }) {
  const host = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!host.current) return;
    const chart = echarts.init(host.current);
    const entries = Object.entries(values);
    chart.setOption({
      animationDuration: 250,
      tooltip: { trigger: 'axis' },
      grid: { left: 32, right: 16, bottom: 28, top: 16, containLabel: true },
      xAxis: { type: 'category', data: entries.map(([status]) => cnLabel(status)), axisLabel: { rotate: 20 } },
      yAxis: { type: 'value', minInterval: 1 },
      series: [{
        type: 'bar',
        data: entries.map(([, count]) => count),
        progressive: 500,
        progressiveThreshold: 3000,
        itemStyle: { color: '#1677ff', borderRadius: [5, 5, 0, 0] },
      }],
    });
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(host.current);
    return () => {
      observer.disconnect();
      chart.dispose();
    };
  }, [values]);

  return <div ref={host} className="status-chart" role="img" aria-label="任务状态分布图" />;
}
