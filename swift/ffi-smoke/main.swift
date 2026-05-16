import Foundation
import ZManagerFFI

let arguments = CommandLine.arguments
guard arguments.count == 3 else {
    FileHandle.standardError.write(Data("usage: ffi-smoke <source> <destination>\n".utf8))
    exit(2)
}

guard zmanager_ffi_healthcheck() else {
    FileHandle.standardError.write(Data("healthcheck failed\n".utf8))
    exit(1)
}

let source = arguments[1]
let zipDestination = arguments[2]
let cleanDestination = "\(zipDestination).clean.tar.zst"

runJob(
    label: "zip",
    source: source,
    destination: zipDestination,
    start: zmanager_ffi_start_zip_create
)

let browserEntry = "\(URL(fileURLWithPath: source).lastPathComponent)/file.txt"
runBrowserSmoke(
    archive: zipDestination,
    entry: browserEntry,
    extractDestination: "\(zipDestination).extract"
)

let fullExtractDestination = "\(zipDestination).full-extract"
runJob(
    label: "extract",
    source: zipDestination,
    destination: fullExtractDestination,
    start: zmanager_ffi_start_extract_archive
)

guard FileManager.default.fileExists(
    atPath: URL(fileURLWithPath: fullExtractDestination)
        .appendingPathComponent(browserEntry)
        .path
) else {
    FileHandle.standardError.write(Data("full archive extract output missing\n".utf8))
    exit(1)
}

if let rawPlan = source.withCString({ zmanager_ffi_plan_clean_source($0) }) {
    let plan = String(cString: rawPlan)
    zmanager_ffi_string_free(rawPlan)
    print(plan)
    guard plan.contains("\"ok\":true") else {
        FileHandle.standardError.write(Data("clean source plan failed: \(plan)\n".utf8))
        exit(1)
    }
}

func runBrowserSmoke(archive: String, entry: String, extractDestination: String) {
    guard let listing = cString(archive.withCString { zmanager_ffi_list_archive($0) }) else {
        FileHandle.standardError.write(Data("archive browser listing returned null\n".utf8))
        exit(1)
    }
    print(listing)
    guard listing.contains("\"ok\":true"), listing.contains("\"path\":\"\(entry)\"") else {
        FileHandle.standardError.write(Data("archive browser listing failed: \(listing)\n".utf8))
        exit(1)
    }

    let extract = archive.withCString { archivePointer in
        entry.withCString { entryPointer in
            extractDestination.withCString { destinationPointer in
                zmanager_ffi_extract_archive_entry(archivePointer, entryPointer, destinationPointer)
            }
        }
    }
    guard let extractResult = cString(extract) else {
        FileHandle.standardError.write(Data("archive browser extract returned null\n".utf8))
        exit(1)
    }
    guard extractResult.contains("\"ok\":true") else {
        FileHandle.standardError.write(Data("archive browser extract failed: \(extractResult)\n".utf8))
        exit(1)
    }
    print(extractResult)

    let extractedPath = URL(fileURLWithPath: extractDestination).appendingPathComponent(entry).path
    guard FileManager.default.fileExists(atPath: extractedPath) else {
        FileHandle.standardError.write(Data("archive browser extract output missing\n".utf8))
        exit(1)
    }

    let preview = archive.withCString { archivePointer in
        entry.withCString { entryPointer in
            zmanager_ffi_preview_archive_entry(archivePointer, entryPointer)
        }
    }
    guard let previewResult = cString(preview) else {
        FileHandle.standardError.write(Data("archive browser preview returned null\n".utf8))
        exit(1)
    }
    guard let previewObject = jsonObject(previewResult),
          previewObject["ok"] as? Bool == true,
          let cleanupRoot = previewObject["cleanup_root"] as? String,
          let previewPath = previewObject["preview_path"] as? String
    else {
        FileHandle.standardError.write(Data("archive browser preview failed: \(previewResult)\n".utf8))
        exit(1)
    }
    print(previewResult)

    guard FileManager.default.fileExists(atPath: previewPath) else {
        FileHandle.standardError.write(Data("archive browser preview output missing\n".utf8))
        exit(1)
    }
    try? FileManager.default.removeItem(atPath: cleanupRoot)
}

func cString(_ raw: UnsafeMutablePointer<CChar>?) -> String? {
    guard let raw else {
        return nil
    }

    defer {
        zmanager_ffi_string_free(raw)
    }

    return String(cString: raw)
}

func jsonObject(_ json: String) -> [String: Any]? {
    guard let data = json.data(using: .utf8) else {
        return nil
    }

    return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
}

runJob(
    label: "clean-source",
    source: source,
    destination: cleanDestination,
    start: zmanager_ffi_start_clean_source_create
)

func runJob(
    label: String,
    source: String,
    destination: String,
    start: (UnsafePointer<CChar>, UnsafePointer<CChar>, UnsafeMutablePointer<OpaquePointer?>)
        -> ZManagerFfiStatus
) {
    var job: OpaquePointer?
    let status = source.withCString { sourcePointer in
        destination.withCString { destinationPointer in
            start(sourcePointer, destinationPointer, &job)
        }
    }

    guard status.rawValue == ZMANAGER_FFI_OK.rawValue, let job else {
        FileHandle.standardError.write(
            Data("failed to start \(label) job: status \(status.rawValue)\n".utf8)
        )
        exit(1)
    }

    var sawCompleted = false
    defer {
        zmanager_ffi_job_free(job)
    }

    while true {
        if let rawEvents = zmanager_ffi_poll_events(job) {
            let events = String(cString: rawEvents)
            zmanager_ffi_string_free(rawEvents)
            if events != "[]" {
                print(events)
            }
            if events.contains("\"type\":\"completed\"") {
                sawCompleted = true
            }
            if events.contains("\"type\":\"failed\"") || events.contains("\"type\":\"cancelled\"") {
                FileHandle.standardError.write(Data("\(label) job did not complete: \(events)\n".utf8))
                exit(1)
            }
        }

        if zmanager_ffi_job_is_finished(job) {
            if let rawEvents = zmanager_ffi_poll_events(job) {
                let events = String(cString: rawEvents)
                zmanager_ffi_string_free(rawEvents)
                if events != "[]" {
                    print(events)
                }
                if events.contains("\"type\":\"completed\"") {
                    sawCompleted = true
                }
            }
            break
        }

        Thread.sleep(forTimeInterval: 0.02)
    }

    guard sawCompleted else {
        FileHandle.standardError.write(Data("\(label) completed event was not observed\n".utf8))
        exit(1)
    }
}
