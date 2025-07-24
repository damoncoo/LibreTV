import path from 'path';
import express from 'express';
import axios from 'axios';
import cors from 'cors';
import { fileURLToPath } from 'url';
import fs from 'fs';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const config = {
  port: process.env.PORT || 8080,
  password: process.env.PASSWORD || '',
  adminpassword: process.env.ADMINPASSWORD || '',
  corsOrigin: process.env.CORS_ORIGIN || '*',
  timeout: parseInt(process.env.REQUEST_TIMEOUT || '5000'),
  maxRetries: parseInt(process.env.MAX_RETRIES || '2'),
  cacheMaxAge: process.env.CACHE_MAX_AGE || '1d',
  userAgent: process.env.USER_AGENT || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
  debug: process.env.DEBUG === 'true'
};

const log = (...args) => {
  if (config.debug) {
    console.log('[DEBUG]', ...args);
  }
};

const app = express();

app.use(cors({
  origin: config.corsOrigin,
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

function sha256Hash(input) {
  return new Promise((resolve) => {
    const hash = crypto.createHash('sha256');
    hash.update(input);
    resolve(hash.digest('hex'));
  });
}

async function renderPage(filePath, password) {
  let content = fs.readFileSync(filePath, 'utf8');
  if (password !== '') {
    const sha256 = await sha256Hash(password);
    content = content.replace('{{PASSWORD}}', sha256);
  }
  // 添加ADMINPASSWORD注入
  if (config.adminpassword !== '') {
      const adminSha256 = await sha256Hash(config.adminpassword);
      content = content.replace('{{ADMINPASSWORD}}', adminSha256);
  } 
  return content;
}

app.get(['/', '/index.html', '/player.html'], async (req, res) => {
  try {
    let filePath;
    switch (req.path) {
      case '/player.html':
        filePath = path.join(__dirname, 'player.html');
        break;
      default: // '/' 和 '/index.html'
        filePath = path.join(__dirname, 'index.html');
        break;
    }
    
    const content = await renderPage(filePath, config.password);
    res.send(content);
  } catch (error) {
    console.error('页面渲染错误:', error);
    res.status(500).send('读取静态页面失败');
  }
});

app.get('/s=:keyword', async (req, res) => {
  try {
    const filePath = path.join(__dirname, 'index.html');
    const content = await renderPage(filePath, config.password);
    res.send(content);
  } catch (error) {
    console.error('搜索页面渲染错误:', error);
    res.status(500).send('读取静态页面失败');
  }
});

function isValidUrl(urlString) {
  try {
    const parsed = new URL(urlString);
    const allowedProtocols = ['http:', 'https:'];
    
    // 从环境变量获取阻止的主机名列表
    const blockedHostnames = (process.env.BLOCKED_HOSTS || 'localhost,127.0.0.1,0.0.0.0,::1').split(',');
    
    // 从环境变量获取阻止的 IP 前缀
    const blockedPrefixes = (process.env.BLOCKED_IP_PREFIXES || '192.168.,10.,172.').split(',');
    
    if (!allowedProtocols.includes(parsed.protocol)) return false;
    if (blockedHostnames.includes(parsed.hostname)) return false;
    
    for (const prefix of blockedPrefixes) {
      if (parsed.hostname.startsWith(prefix)) return false;
    }
    
    return true;
  } catch {
    return false;
  }
}

// 修复反向代理处理过的路径
app.use('/proxy', (req, res, next) => {
  const targetUrl = req.url.replace(/^\//, '').replace(/(https?:)\/([^/])/, '$1//$2');
  req.url = '/' + encodeURIComponent(targetUrl);
  next();
});

// 代理路由
app.get('/proxy/:encodedUrl', async (req, res) => {
  try {
    const encodedUrl = req.params.encodedUrl;
    const targetUrl = decodeURIComponent(encodedUrl);

    // 安全验证
    if (!isValidUrl(targetUrl)) {
      return res.status(400).send('无效的 URL');
    }

    log(`代理请求: ${targetUrl}`);

    // 添加请求超时和重试逻辑
    const maxRetries = config.maxRetries;
    let retries = 0;
    
    const makeRequest = async () => {
      try {
        return await axios({
          method: 'get',
          url: targetUrl,
          responseType: 'stream',
          timeout: config.timeout,
          headers: {
            'User-Agent': config.userAgent
          }
        });
      } catch (error) {
        if (retries < maxRetries) {
          retries++;
          log(`重试请求 (${retries}/${maxRetries}): ${targetUrl}`);
          return makeRequest();
        }
        throw error;
      }
    };

    const response = await makeRequest();

    // 转发响应头（过滤敏感头）
    const headers = { ...response.headers };
    const sensitiveHeaders = (
      process.env.FILTERED_HEADERS || 
      'content-security-policy,cookie,set-cookie,x-frame-options,access-control-allow-origin'
    ).split(',');
    
    sensitiveHeaders.forEach(header => delete headers[header]);
    res.set(headers);

    // 管道传输响应流
    response.data.pipe(res);
  } catch (error) {
    console.error('代理请求错误:', error.message);
    if (error.response) {
      res.status(error.response.status || 500);
      error.response.data.pipe(res);
    } else {
      res.status(500).send(`请求失败: ${error.message}`);
    }
  }
});

// Apple TV API Routes
app.get('/api/recommendations', async (req, res) => {
  try {
    const includeAdult = req.query.includeAdult === 'true';
    const apiConfig = getApiConfig(includeAdult);

    // Get recommendations from multiple sources (excluding adult sources by default)
    const sources = Object.keys(apiConfig).filter(key =>
      includeAdult || !apiConfig[key].adult
    ).slice(0, 5); // Limit to first 5 sources for performance

    const recommendations = [];

    for (const source of sources) {
      try {
        // Fetch multiple pages to get more content
        const pages = [1, 2];
        for (const page of pages) {
          const apiUrl = `${apiConfig[source].api}?ac=videolist&pg=${page}`;
          const response = await axios({
            method: 'get',
            url: apiUrl,
            timeout: config.timeout,
            headers: {
              'User-Agent': config.userAgent
            }
          });

          if (response.data && response.data.list) {
            const movies = response.data.list.map(movie => ({
              id: movie.vod_id,
              title: movie.vod_name,
              poster: movie.vod_pic,
              year: movie.vod_year,
              area: movie.vod_area,
              type: movie.type_name,
              remarks: movie.vod_remarks,
              source: source,
              sourceName: apiConfig[source].name,
              adult: apiConfig[source].adult || false
            }));
            recommendations.push(...movies);
          }
        }
      } catch (error) {
        log(`Failed to fetch from ${source}:`, error.message);
      }
    }

    // Shuffle and limit results
    const shuffled = recommendations.sort(() => 0.5 - Math.random());

    res.json({
      success: true,
      data: shuffled.slice(0, 100) // Increased to 100 recommendations
    });
  } catch (error) {
    console.error('Recommendations API error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch recommendations'
    });
  }
});

app.get('/api/search', async (req, res) => {
  try {
    const query = req.query.q;
    if (!query) {
      return res.status(400).json({
        success: false,
        error: 'Search query is required'
      });
    }

    const source = req.query.source;
    const includeAdult = req.query.includeAdult === 'true';
    const aggregated = req.query.aggregated === 'true';

    const apiConfig = getApiConfig(includeAdult);

    if (aggregated) {
      // Aggregated search across all sources
      const allResults = [];
      const searchPromises = [];

      for (const [sourceKey, sourceConfig] of Object.entries(apiConfig)) {
        const searchPromise = axios({
          method: 'get',
          url: `${sourceConfig.api}?ac=videolist&wd=${encodeURIComponent(query)}`,
          timeout: config.timeout,
          headers: {
            'User-Agent': config.userAgent
          }
        }).then(response => {
          if (response.data && response.data.list) {
            return response.data.list.map(movie => ({
              id: movie.vod_id,
              title: movie.vod_name,
              poster: movie.vod_pic,
              year: movie.vod_year,
              area: movie.vod_area,
              type: movie.type_name,
              remarks: movie.vod_remarks,
              director: movie.vod_director,
              actor: movie.vod_actor,
              source: sourceKey,
              sourceName: sourceConfig.name,
              adult: sourceConfig.adult || false
            }));
          }
          return [];
        }).catch(error => {
          console.error(`Search failed for source ${sourceKey}:`, error.message);
          return [];
        });

        searchPromises.push(searchPromise);
      }

      const results = await Promise.all(searchPromises);
      const flatResults = results.flat();

      // Remove duplicates based on title and year
      const uniqueResults = [];
      const seen = new Set();

      for (const movie of flatResults) {
        const key = `${movie.title}-${movie.year}`;
        if (!seen.has(key)) {
          seen.add(key);
          uniqueResults.push(movie);
        }
      }

      res.json({
        success: true,
        data: uniqueResults.slice(0, 1000), // Limit results
        sources: Object.keys(apiConfig).length,
        aggregated: true
      });
    } else {
      // Single source search
      const sourceKey = source || 'heimuer';

      if (!apiConfig[sourceKey]) {
        return res.status(400).json({
          success: false,
          error: 'Invalid source'
        });
      }

      const apiUrl = `${apiConfig[sourceKey].api}?ac=videolist&wd=${encodeURIComponent(query)}`;

      const response = await axios({
        method: 'get',
        url: apiUrl,
        timeout: config.timeout,
        headers: {
          'User-Agent': config.userAgent
        }
      });

      if (response.data && response.data.list) {
        const movies = response.data.list.map(movie => ({
          id: movie.vod_id,
          title: movie.vod_name,
          poster: movie.vod_pic,
          year: movie.vod_year,
          area: movie.vod_area,
          type: movie.type_name,
          remarks: movie.vod_remarks,
          director: movie.vod_director,
          actor: movie.vod_actor,
          source: sourceKey,
          sourceName: apiConfig[sourceKey].name,
          adult: apiConfig[sourceKey].adult || false
        }));

        res.json({
          success: true,
          data: movies
        });
      } else {
        res.json({
          success: true,
          data: []
        });
      }
    }
  } catch (error) {
    console.error('Search API error:', error);
    res.status(500).json({
      success: false,
      error: 'Search failed'
    });
  }
});

app.get('/api/movie/:id', async (req, res) => {
  try {
    const movieId = req.params.id;
    const source = req.query.source || 'heimuer';
    const apiConfig = getApiConfig();

    if (!apiConfig[source]) {
      return res.status(400).json({
        success: false,
        error: 'Invalid source'
      });
    }

    const apiUrl = `${apiConfig[source].api}?ac=videolist&ids=${movieId}`;

    const response = await axios({
      method: 'get',
      url: apiUrl,
      timeout: config.timeout,
      headers: {
        'User-Agent': config.userAgent
      }
    });

    if (response.data && response.data.list && response.data.list.length > 0) {
      const movie = response.data.list[0];

      // Extract video URLs
      let episodes = [];
      if (movie.vod_play_url) {
        const playSources = movie.vod_play_url.split('$$$');
        if (playSources.length > 0) {
          const mainSource = playSources[0];
          const episodeList = mainSource.split('#');

          episodes = episodeList.map((ep, index) => {
            const parts = ep.split('$');
            return {
              episode: index + 1,
              title: parts.length > 1 ? parts[0] : `Episode ${index + 1}`,
              url: parts.length > 1 ? parts[1] : parts[0]
            };
          }).filter(ep => ep.url && (ep.url.startsWith('http://') || ep.url.startsWith('https://')));
        }
      }

      const movieDetail = {
        id: movie.vod_id,
        title: movie.vod_name,
        poster: movie.vod_pic,
        description: movie.vod_content,
        year: movie.vod_year,
        area: movie.vod_area,
        type: movie.type_name,
        director: movie.vod_director,
        actor: movie.vod_actor,
        remarks: movie.vod_remarks,
        episodes: episodes,
        source: source,
        sourceName: apiConfig[source].name
      };

      res.json({
        success: true,
        data: movieDetail
      });
    } else {
      res.status(404).json({
        success: false,
        error: 'Movie not found'
      });
    }
  } catch (error) {
    console.error('Movie detail API error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch movie details'
    });
  }
});

app.get('/api/sources', async (req, res) => {
  try {
    const includeAdult = req.query.includeAdult === 'true';
    const apiConfig = getApiConfig(includeAdult);

    const sources = Object.entries(apiConfig).map(([key, config]) => ({
      key,
      name: config.name,
      adult: config.adult || false
    }));

    res.json({
      success: true,
      data: sources
    });
  } catch (error) {
    console.error('Sources API error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch sources'
    });
  }
});

app.get('/api/categories', async (req, res) => {
  try {
    const categories = [
      { "id": 1, "name": "电影", "type": "1", "categoryType": "content", "color": "#FF6B6B" },
      { "id": 2, "name": "电视剧", "type": "2", "categoryType": "content", "color": "#4ECDC4" },
    
      { "id": 10, "name": "热门", "type": "hot", "categoryType": "trending", "color": "#FF6B6B" },
      { "id": 11, "name": "最新", "type": "latest", "categoryType": "trending", "color": "#45B7D1" },
      { "id": 12, "name": "经典", "type": "classic", "categoryType": "trending", "color": "#96CEB4" },
      { "id": 13, "name": "豆瓣高分", "type": "douban_high", "categoryType": "rating", "color": "#FFEAA7" },
      { "id": 14, "name": "冷门佳片", "type": "hidden_gems", "categoryType": "rating", "color": "#DDA0DD", "isHighlighted": true },
    
      { "id": 20, "name": "华语", "type": "chinese", "categoryType": "region", "color": "#FF7675" },
      { "id": 21, "name": "欧美", "type": "western", "categoryType": "region", "color": "#74B9FF" },
      { "id": 22, "name": "韩国", "type": "korean", "categoryType": "region", "color": "#FD79A8" },
      { "id": 23, "name": "日本", "type": "japanese", "categoryType": "region", "color": "#FDCB6E" },
    
      { "id": 30, "name": "动作", "type": "action", "categoryType": "genre", "color": "#E17055" },
      { "id": 31, "name": "喜剧", "type": "comedy", "categoryType": "genre", "color": "#00B894" },
      { "id": 32, "name": "爱情", "type": "romance", "categoryType": "genre", "color": "#E84393" },
      { "id": 33, "name": "科幻", "type": "scifi", "categoryType": "genre", "color": "#0984E3" },
      { "id": 34, "name": "悬疑", "type": "mystery", "categoryType": "genre", "color": "#6C5CE7" },
      { "id": 35, "name": "恐怖", "type": "horror", "categoryType": "genre", "color": "#2D3436" },
      { "id": 36, "name": "治愈", "type": "healing", "categoryType": "genre", "color": "#00CEC9" }
    ]
    res.json({
      success: true,
      data: categories
    });
  } catch (error) {
    console.error('Categories API error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch categories'
    });
  }
});

// Get movies by category
app.get('/api/category/:type', async (req, res) => {
  try {
    const categoryType = req.params.type;
    const page = parseInt(req.query.page) || 1;
    const source = req.query.source || 'heimuer';

    // Validate category type
    const validTypes = ['1', '2', '3', '4', '6'];
    if (!validTypes.includes(categoryType)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid category type'
      });
    }

    const apiConfig = getApiConfig();
    if (!apiConfig[source]) {
      return res.status(400).json({
        success: false,
        error: 'Invalid source'
      });
    }

    const apiUrl = `${apiConfig[source].api}?ac=videolist&t=${categoryType}&pg=${page}`;

    const response = await axios({
      method: 'get',
      url: apiUrl,
      timeout: config.timeout,
      headers: {
        'User-Agent': config.userAgent
      }
    });

    if (response.data && response.data.list) {
      const movies = response.data.list.map(movie => ({
        id: movie.vod_id,
        title: movie.vod_name,
        poster: movie.vod_pic,
        year: movie.vod_year,
        area: movie.vod_area,
        type: movie.type_name,
        remarks: movie.vod_remarks,
        source: source,
        sourceName: apiConfig[source].name
      }));

      res.json({
        success: true,
        data: movies,
        pagination: {
          currentPage: page,
          totalPages: response.data.pagecount || 1,
          totalItems: response.data.total || movies.length
        }
      });
    } else {
      res.json({
        success: true,
        data: [],
        pagination: {
          currentPage: page,
          totalPages: 0,
          totalItems: 0
        }
      });
    }
  } catch (error) {
    console.error('Category API error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch category movies'
    });
  }
});

// Helper function to get API configuration
function getApiConfig(includeAdult = false) {
  const config = {
    dyttzy: {
      api: 'http://caiji.dyttzyapi.com/api.php/provide/vod',
      name: '电影天堂资源',
      detail: 'http://caiji.dyttzyapi.com'
    },
    ruyi: {
      api: 'https://cj.rycjapi.com/api.php/provide/vod',
      name: '如意资源'
    },
    bfzy: {
      api: 'https://bfzyapi.com/api.php/provide/vod',
      name: '暴风资源'
    },
    tyyszy: {
      api: 'https://tyyszy.com/api.php/provide/vod',
      name: '天涯资源'
    },
    ffzy: {
      api: 'http://ffzy5.tv/api.php/provide/vod',
      name: '非凡影视',
      detail: 'http://ffzy5.tv'
    },
    heimuer: {
      api: 'https://json.heimuer.xyz/api.php/provide/vod',
      name: '黑木耳',
      detail: 'https://heimuer.tv'
    },
    zy360: {
      api: 'https://360zy.com/api.php/provide/vod',
      name: '360资源'
    },
    iqiyi: {
      api: 'https://www.iqiyizyapi.com/api.php/provide/vod',
      name: 'iqiyi资源'
    },
    wolong: {
      api: 'https://wolongzyw.com/api.php/provide/vod',
      name: '卧龙资源'
    },
    hwba: {
      api: 'https://cjhwba.com/api.php/provide/vod',
      name: '华为吧资源'
    },
    jisu: {
      api: 'https://jszyapi.com/api.php/provide/vod',
      name: '极速资源',
      detail: 'https://jszyapi.com'
    },
    dbzy: {
      api: 'https://dbzy.tv/api.php/provide/vod',
      name: '豆瓣资源'
    },
    mozhua: {
      api: 'https://mozhuazy.com/api.php/provide/vod',
      name: '魔爪资源'
    },
    mdzy: {
      api: 'https://www.mdzyapi.com/api.php/provide/vod',
      name: '魔都资源'
    },
    zuid: {
      api: 'https://api.zuidapi.com/api.php/provide/vod',
      name: '最大资源'
    },
    yinghua: {
      api: 'https://m3u8.apiyhzy.com/api.php/provide/vod',
      name: '樱花资源'
    },
    baidu: {
      api: 'https://api.apibdzy.com/api.php/provide/vod',
      name: '百度云资源'
    },
    wujin: {
      api: 'https://api.wujinapi.me/api.php/provide/vod',
      name: '无尽资源'
    },
    wwzy: {
      api: 'https://wwzy.tv/api.php/provide/vod',
      name: '旺旺短剧'
    },
    ikun: {
      api: 'https://ikunzyapi.com/api.php/provide/vod',
      name: 'iKun资源'
    }
  };

  // Add adult content sources if requested
  if (includeAdult) {
    config.testSource = {
      api: 'https://www.example.com/api.php/provide/vod',
      name: '空内容测试源',
      adult: true
    };

  }
  return config;
}

app.use(express.static(path.join(__dirname), {
  maxAge: config.cacheMaxAge
}));

app.use((err, req, res, next) => {
  console.error('服务器错误:', err);
  res.status(500).send('服务器内部错误');
});

app.use((req, res) => {
  res.status(404).send('页面未找到');
});

// 启动服务器
app.listen(config.port, () => {
  console.log(`服务器运行在 http://localhost:${config.port}`);
  console.log('Apple TV API endpoints available:');
  console.log('  GET /api/recommendations - Get featured movies');
  console.log('  GET /api/search?q=query - Search movies');
  console.log('  GET /api/movie/:id?source=source - Get movie details');
  console.log('  GET /api/categories - Get movie categories');

  if (config.password !== '') {
    console.log('用户登录密码已设置');
  }
  if (config.adminpassword !== '') {
    console.log('管理员登录密码已设置');
  }
  if (config.debug) {
    console.log('调试模式已启用');
    console.log('配置:', { ...config, password: config.password ? '******' : '', adminpassword: config.adminpassword? '******' : '' });
  }
});
