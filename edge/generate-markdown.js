import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const projectRoot = path.resolve(__dirname, '..');

const resultsPath = path.join(projectRoot, 'all_working_proxies.txt');
const outputPath = path.join(projectRoot, 'sub', 'ProxyIP-Daily.md');
const outputDir = path.dirname(outputPath);

function groupProxiesByCountry(proxies) {
  const grouped = {};
  
  proxies.forEach(proxy => {
    const country = proxy.country || 'Unknown';
    if (!grouped[country]) {
      grouped[country] = [];
    }
    grouped[country].push(proxy);
  });
  
  return grouped;
}

function groupProxiesByPort(proxies) {
  const grouped = {};
  
  proxies.forEach(proxy => {
    const port = proxy.port || 'Unknown';
    if (!grouped[port]) {
      grouped[port] = [];
    }
    grouped[port].push(proxy);
  });
  
  return grouped;
}

function generateStats(proxies) {
  const countries = new Set(proxies.map(p => p.country)).size;
  const ports = new Set(proxies.map(p => p.port)).size;
  const methods = {};
  
  proxies.forEach(proxy => {
    const method = proxy.method || 'Unknown';
    methods[method] = (methods[method] || 0) + 1;
  });
  
  return { countries, ports, methods };
}

try {
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  let proxies = [];
  if (fs.existsSync(resultsPath)) {
    const rawContent = fs.readFileSync(resultsPath, 'utf-8');
    if (rawContent.trim() !== '') {
      const lines = rawContent.split(/\r?\n/).filter(line => line.trim() !== '');
      proxies = lines.map(line => {
        try {
          return JSON.parse(line);
        } catch (e) {
          console.log(`Failed to parse line: ${line}`);
          return null;
        }
      }).filter(proxy => proxy !== null);
    }
  }

  proxies.sort((a, b) => {
    const countryCompare = (a.country || '').localeCompare(b.country || '');
    if (countryCompare !== 0) return countryCompare;
    return (a.ip || '').localeCompare(b.ip || '');
  });

  const stats = generateStats(proxies);
  const groupedByCountry = groupProxiesByCountry(proxies);
  const groupedByPort = groupProxiesByPort(proxies);

  let markdownContent = `# 🌐 Daily Proxy Test Results (Port 443)\n\n`;
  markdownContent += `**Last updated:** ${new Date().toUTCString()}\n\n`;
  
  markdownContent += `## 📊 Summary\n\n`;
  markdownContent += `- **Total working proxies:** ${proxies.length}\n`;
  markdownContent += `- **Countries covered:** ${stats.countries}\n`;
  markdownContent += `- **Different ports:** ${stats.ports}\n`;
  markdownContent += `- **Success methods:** ${Object.entries(stats.methods).map(([method, count]) => `${method} (${count})`).join(', ')}\n\n`;

  if (Object.keys(groupedByPort).length > 0) {
    markdownContent += `## 🔌 Ports Distribution\n\n`;
    const sortedPorts = Object.entries(groupedByPort)
      .sort(([,a], [,b]) => b.length - a.length)
      .slice(0, 10);
    
    markdownContent += `| Port | Count | Percentage |\n`;
    markdownContent += `|------|-------|------------|\n`;
    
    sortedPorts.forEach(([port, proxiesInPort]) => {
      const percentage = ((proxiesInPort.length / proxies.length) * 100).toFixed(1);
      markdownContent += `| ${port} | ${proxiesInPort.length} | ${percentage}% |\n`;
    });
    markdownContent += `\n`;
  }

  if (proxies.length > 0) {
    markdownContent += `## 🗺️ Working Proxies by Country\n\n`;
    
    const sortedCountries = Object.entries(groupedByCountry)
      .sort(([,a], [,b]) => b.length - a.length);

    sortedCountries.forEach(([country, countryProxies]) => {
      markdownContent += `### ${country} (${countryProxies.length} proxies)\n\n`;
      markdownContent += `| Proxy IP | City | Method | ISP / Organization |\n`;
      markdownContent += `|----------|------|--------|--------------------||\n`;

      countryProxies.forEach(proxy => {
        const ip = proxy.ip || 'N/A';
        const city = proxy.city || 'N/A';
        const method = proxy.method || 'N/A';
        const isp = (proxy.as || 'N/A').substring(0, 50);

        markdownContent += `| \`${ip}:443\` | ${city} | ${method} | ${isp} |\n`;
      });
      
      markdownContent += `\n`;
    });

    markdownContent += `## 📋 All Working Proxies - Port 443 (Copy-Friendly Format)\n\n`;
    markdownContent += `\`\`\`\n`;
    proxies.forEach(proxy => {
      markdownContent += `${proxy.ip}:443\n`;
    });
    markdownContent += `\`\`\`\n\n`;
    
    markdownContent += `## 💾 JSON Format\n\n`;
    markdownContent += `<details>\n<summary>Click to expand JSON data</summary>\n\n`;
    markdownContent += `\`\`\`json\n`;
    markdownContent += JSON.stringify(proxies, null, 2);
    markdownContent += `\n\`\`\`\n\n`;
    markdownContent += `</details>\n\n`;
    
  } else {
    markdownContent += `## ❌ No Working Proxies Found\n\n`;
    markdownContent += `No working proxies were found in this test run. This could be due to:\n\n`;
    markdownContent += `- Network connectivity issues\n`;
    markdownContent += `- All proxies in the input file are currently offline\n`;
    markdownContent += `- The proxy test criteria may be too strict\n\n`;
  }

  markdownContent += `---\n`;
  markdownContent += `*Generated by Proxy IP Tester | Next update: ${new Date(Date.now() + 48*60*60*1000).toUTCString()}*\n`;

  fs.writeFileSync(outputPath, markdownContent);
  console.log(
    `Successfully generated ${path.basename(outputPath)} with ${proxies.length} proxies.`,
  );
  
  const statsFile = path.join(projectRoot, 'proxy-stats.json');
  const statsData = {
    lastUpdate: new Date().toISOString(),
    totalProxies: proxies.length,
    countries: stats.countries,
    ports: stats.ports,
    methods: stats.methods,
    topCountries: Object.entries(groupedByCountry)
      .sort(([,a], [,b]) => b.length - a.length)
      .slice(0, 10)
      .map(([country, proxiesInCountry]) => ({
        country,
        count: proxiesInCountry.length
      })),
    topPorts: Object.entries(groupedByPort)
      .sort(([,a], [,b]) => b.length - a.length)
      .slice(0, 10)
      .map(([port, proxiesInPort]) => ({
        port: parseInt(port),
        count: proxiesInPort.length
      }))
  };
  
  fs.writeFileSync(statsFile, JSON.stringify(statsData, null, 2));
  
} catch (error) {
  console.error('An error occurred in generate-markdown.js:', error);
  process.exit(1);
}
