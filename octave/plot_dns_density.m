function plot_dns_density(ts)
  record_count = length(ts);
  hits = ones(record_count);
  plot(ts, hits, 'linestyle', 'none', 'marker', '.');
endfunction

