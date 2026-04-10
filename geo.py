import requests
import ipaddress

geo_cache = {}
MAX_CACHE_SIZE = 1000


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False


def get_ip_location(ip):

    # ================= CACHE =================
    if ip in geo_cache:
        return geo_cache[ip]

    # ================= PRIVATE IP =================
    if is_private_ip(ip):
        result = {
            "ip": ip,
            "city": "Local Network",
            "country": "Private",
            "org": "Internal Traffic",
            "lat": None,
            "lon": None
        }
        geo_cache[ip] = result
        return result

    # ================= API 1: ipinfo =================
    try:
        url = f"https://ipinfo.io/{ip}/json"
        headers = {"User-Agent": "Mozilla/5.0"}

        res = requests.get(url, timeout=5, headers=headers)
        res.raise_for_status()

        response = res.json()

        if "loc" in response:
            lat, lon = response["loc"].split(",")

            result = {
                "ip": ip,
                "city": response.get("city", "Unknown"),
                "country": response.get("country", "Unknown"),
                "org": response.get("org", "Unknown"),
                "lat": float(lat),
                "lon": float(lon)
            }

            # cache limit
            if len(geo_cache) > MAX_CACHE_SIZE:
                geo_cache.pop(next(iter(geo_cache)))

            geo_cache[ip] = result
            return result

    except Exception as e:
        print("ipinfo error:", e)

    # ================= API 2: BACKUP (ip-api) =================
    try:
        url = f"http://ip-api.com/json/{ip}"
        res = requests.get(url, timeout=5)

        data = res.json()

        if data.get("status") == "success":
            result = {
                "ip": ip,
                "city": data.get("city", "Unknown"),
                "country": data.get("country", "Unknown"),
                "org": data.get("isp", "Unknown"),
                "lat": data.get("lat"),
                "lon": data.get("lon")
            }

            # cache limit
            if len(geo_cache) > MAX_CACHE_SIZE:
                geo_cache.pop(next(iter(geo_cache)))

            geo_cache[ip] = result
            return result

    except Exception as e:
        print("ip-api error:", e)

    # ================= FINAL FALLBACK =================
    result = {
        "ip": ip,
        "city": "Unknown",
        "country": "Unknown",
        "org": "Unknown",
        "lat": None,
        "lon": None
    }

    geo_cache[ip] = result
    return result