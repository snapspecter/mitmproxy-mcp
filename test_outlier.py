import asyncio
import json
import httpx
from mitmproxy_mcp.core import server
from mitmproxy_mcp.core.server import start_proxy, get_traffic_summary

async def main():
    print("Starting proxy...")
    res = await start_proxy(8080)
    print("start_proxy returned:", res)
    await asyncio.sleep(5)
    
    print("Making request to outlier.bet...")
    proxies = "http://127.0.0.1:8080"
    try:
        async with httpx.AsyncClient(proxy=proxies, verify=False) as client:
            resp = await client.get("https://outlier.bet/")
            print(f"Request status: {resp.status_code}")
    except Exception as e:
        print("Error:", e)
    
    await asyncio.sleep(2)
    print("Getting traffic summary...")
    summary_json = await get_traffic_summary(50)
    summary = json.loads(summary_json)
    
    print(json.dumps(summary, indent=2))
        
    print("Stopping proxy...")
    await server.stop_proxy()
    await asyncio.sleep(2)
    print("Done")

if __name__ == "__main__":
    asyncio.run(main())
