import base64

from conftest import authorize


PNG_1PX=base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/FZkAAAAASUVORK5CYII=")


def test_private_screenshot_upload_requires_index_and_current_authorization(system,admin_headers):
    client,_,_=system
    path="/api/admin/hosts/127.0.0.7/screenshots"
    headers={"Content-Type":"image/png","X-Screenshot-Name":"capture.png"}
    assert client.post(path,headers=headers,content=PNG_1PX).status_code==401
    authorize(client,admin_headers)
    rejected=client.post(path,headers={**headers,**admin_headers},content=PNG_1PX)
    assert rejected.status_code==404
    imported=client.post("/api/admin/import",headers=admin_headers,json={"provenance":"screenshot-fixture","observations":[{"ip":"127.0.0.7","port":443,"service":"https"}]})
    assert imported.status_code==200
    saved=client.post(path,headers={**headers,**admin_headers,"X-Screenshot-Note":"verified local asset"},content=PNG_1PX)
    assert saved.status_code==200
    screenshot=saved.json()
    listing=client.get("/api/admin/screenshots",headers=admin_headers).json()
    assert len(listing["screenshots"])==1 and listing["screenshots"][0]["ip"]=="127.0.0.7"
    content=client.get(f"/api/admin/screenshots/{screenshot['id']}/content",headers=admin_headers)
    assert content.status_code==200 and content.content==PNG_1PX
    assert content.headers["cache-control"]=="private, no-store"
    assert content.headers["x-content-type-options"]=="nosniff"
    client.post("/api/admin/authorizations/1/revoke",headers=admin_headers)
    assert client.get("/api/admin/screenshots",headers=admin_headers).json()["screenshots"]==[]
    assert client.get(f"/api/admin/screenshots/{screenshot['id']}/content",headers=admin_headers).status_code==403


def test_screenshot_rejects_svg_and_mismatched_image_data(system,admin_headers):
    client,_,_=system
    path="/api/admin/hosts/127.0.0.7/screenshots"
    svg=client.post(path,headers={**admin_headers,"Content-Type":"image/svg+xml","X-Screenshot-Name":"x.svg"},content=b"<svg/>")
    assert svg.status_code==415
    mismatch=client.post(path,headers={**admin_headers,"Content-Type":"image/png","X-Screenshot-Name":"x.png"},content=b"not a png")
    assert mismatch.status_code==415
