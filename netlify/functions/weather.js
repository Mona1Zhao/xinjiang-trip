const ALLOWED_CITIES = new Set([
  "650100", // 乌鲁木齐
  "652701", // 博乐
  "654003", // 奎屯
  "654321", // 布尔津
  "654324", // 哈巴河
  "654301", // 阿勒泰
]);

const json = (statusCode, body, extraHeaders = {}) => ({
  statusCode,
  headers: {
    "content-type": "application/json; charset=utf-8",
    "cache-control": statusCode === 200 ? "public, max-age=900" : "no-store",
    ...extraHeaders,
  },
  body: JSON.stringify(body),
});

exports.handler = async (event) => {
  if (event.httpMethod !== "GET") {
    return json(405, { ok: false, error: "METHOD_NOT_ALLOWED" }, { allow: "GET" });
  }

  const city = String(event.queryStringParameters?.city || "").trim();
  if (!ALLOWED_CITIES.has(city)) {
    return json(400, { ok: false, error: "UNSUPPORTED_CITY" });
  }

  const key = process.env.AMAP_WEB_KEY;
  if (!key) {
    return json(503, { ok: false, error: "WEATHER_NOT_CONFIGURED" });
  }

  const url = new URL("https://restapi.amap.com/v3/weather/weatherInfo");
  url.searchParams.set("key", key);
  url.searchParams.set("city", city);
  url.searchParams.set("extensions", "all");
  url.searchParams.set("output", "JSON");

  try {
    const response = await fetch(url, { headers: { accept: "application/json" } });
    const data = await response.json();
    if (!response.ok || data.status !== "1" || !Array.isArray(data.forecasts)) {
      return json(502, { ok: false, error: "WEATHER_PROVIDER_ERROR" });
    }

    const forecast = data.forecasts[0];
    return json(200, {
      ok: true,
      city: forecast.city,
      adcode: forecast.adcode,
      reporttime: forecast.reporttime,
      casts: (forecast.casts || []).map((cast) => ({
        date: cast.date,
        week: cast.week,
        dayweather: cast.dayweather,
        nightweather: cast.nightweather,
        daytemp: cast.daytemp,
        nighttemp: cast.nighttemp,
        daywind: cast.daywind,
        nightwind: cast.nightwind,
        daypower: cast.daypower,
        nightpower: cast.nightpower,
      })),
    });
  } catch (_) {
    return json(502, { ok: false, error: "WEATHER_UNAVAILABLE" });
  }
};
