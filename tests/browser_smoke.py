"""Verify the local worker, comparison, privacy controls and reset from the browser."""
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

root = Path(__file__).resolve().parents[1]
fixture = subprocess.check_output(["node", "--input-type=module", "-e",
    "import{sampleCapture}from './tests/fixtures/captures.mjs';process.stdout.write(Buffer.from(sampleCapture()));"], cwd=root)
frame_length = struct.unpack_from("<I",fixture,32)[0]
frame = fixture[40:40+frame_length]
pad = frame + bytes((-len(frame)) % 4)
section = struct.pack("<IIIHHqI",0x0a0d0d0a,28,0x1a2b3c4d,1,0,-1,28)
interface = struct.pack("<IIHHII",1,20,1,0,65535,20)
simple = struct.pack("<III",3,len(pad)+16,len(frame))+pad+struct.pack("<I",len(pad)+16)
second = section+interface+simple

def upload(selector,name,data):
    page.locator(selector).set_input_files({"name":name,"mimeType":"application/octet-stream","buffer":data})

def downloaded(button):
    with page.expect_download() as result:
        page.locator(button).click()
    return json.loads(Path(result.value.path()).read_bytes())

with sync_playwright() as playwright:
    browser = playwright.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH"))
    for width in (390,1200):
        page = browser.new_page(viewport={"width":width, "height":850},accept_downloads=True)
        errors = []
        page.on("pageerror",lambda error:errors.append(str(error)))
        page.goto(sys.argv[1])
        upload("#file","first-private.pcap",fixture)
        expect(page.locator("#report")).to_be_visible()
        expect(page.locator("#stats")).to_contain_text("Packet records")
        upload("#second-file","second-private.pcapng",second)
        expect(page.locator("#comparison")).to_be_visible()
        expect(page.locator("#compare-protocols")).to_contain_text("+75 pp")
        report = downloaded("#compare-export")
        assert report["second"]["missingTimestamps"] == 1 and report["second"]["spanSeconds"] is None
        assert report["first"]["records"] == 8
        page.locator("#flows button").first.click()
        expect(page.locator("#direction-report")).to_be_visible()
        expect(page.locator("#directions tr")).to_have_count(2)
        page.locator("#clear-flow").click()
        page.locator("#protocol").select_option("DNS")
        page.locator("#timeline-measure").select_option("wireBytes")
        expect(page.locator("#timeline-note")).to_contain_text("wire bytes")
        combined = downloaded("#aggregate-export")
        assert combined["summary"]["records"] == 2
        assert sum(b["packets"] for b in combined["timeline"]["bins"]) == 2
        assert sum(b["wireBytes"] for b in combined["timeline"]["bins"]) == combined["summary"]["wireBytes"]
        serialized = json.dumps([combined,report])
        for forbidden in ["192.0.2.", "demo.example", "1735689600","first-private","second-private"]:
            assert forbidden not in serialized
        details = downloaded("#export")
        assert len(details["packets"]) == 2 and "source" in details["packets"][0]
        upload("#second-file","invalid.pcap",b"invalid")
        expect(page.locator("#compare-status")).to_contain_text("Unknown capture format")
        upload("#second-file","empty.pcap",fixture[:24])
        expect(page.locator("#compare-names")).to_contain_text("empty.pcap")
        assert downloaded("#compare-export")["second"]["records"] == 0
        page.locator("#remove-second").click()
        expect(page.locator("#comparison")).to_be_hidden()
        upload("#file","partial.pcap",fixture[:-1])
        expect(page.locator("#notes")).to_contain_text("incomplete")
        assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.locator("#clear").click()
        expect(page.locator("#report")).to_be_hidden()
        assert not errors,errors
        page.close()
print("Verified both capture formats, whole-file comparison, direction counts, byte timeline, exports and empty/partial capture handling at 390 and 1200 pixels.")
