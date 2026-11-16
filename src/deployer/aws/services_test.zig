//! Tests for `services.zig`: commonware's `services.rs` tests, and SHA-256 conformance hashes
//! of every generated script, unit, and config, taken from commonware's own output
//! (commonware 2026.10.0, `services.rs` built with the inputs below).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Io = std.Io;
const services = @import("services.zig");
const Architecture = @import("mod.zig").Architecture;

const gpa = testing.allocator;
const Targets = []const services.ScrapeTarget;
const write_monitoring_download = services.write_install_monitoring_download_cmd;
const load_format = "sudo docker load -i {s}/images/{s}";
const home = services.home_directory;

/// The output of `write(writer, args...)`, owned by the caller.
fn output(comptime write: anytype, args: anytype) ![]u8 {
    var out: Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    _ = try @call(.auto, write, .{&out.writer} ++ args);
    return out.toOwnedSlice();
}

fn expect_sha256(expected_hex: *const [64]u8, text: []const u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(text, &digest, .{});
    const actual = std.fmt.bytesToHex(digest, .lower);
    try testing.expectEqualStrings(expected_hex, &actual);
}

fn contains(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

fn image_file_name(buffer: []u8, image: []const u8) ![]const u8 {
    var writer: Io.Writer = .fixed(buffer);
    try services.write_image_file_name(&writer, image);
    return writer.buffered();
}

const monitoring_image_urls = blk: {
    var urls: [services.monitoring_images.len]services.ImageUrl = undefined;
    for (services.monitoring_images, &urls) |image, *url| {
        url.* = .{ .image = image, .url = "image-url-" ++ image };
    }
    const final = urls;
    break :blk final;
};

const binary_image_urls = blk: {
    var urls: [services.binary_images.len]services.ImageUrl = undefined;
    for (services.binary_images, &urls) |image, *url| {
        url.* = .{ .image = image, .url = "image-url-" ++ image };
    }
    const final = urls;
    break :blk final;
};

const monitoring_urls: services.MonitoringUrls = .{
    .docker_tgz = "docker",
    .prometheus_config = "prometheus-config",
    .datasources_yml = "datasources",
    .all_yml = "dashboards",
    .dashboard = "dashboard",
    .node_exporter_dashboard = "node-exporter-dashboard",
    .loki_yml = "loki-config",
    .pyroscope_yml = "pyroscope-config",
    .tempo_yml = "tempo-config",
    .images = &monitoring_image_urls,
};

const instance_urls: services.InstanceUrls = .{
    .binary = "binary",
    .config = "config",
    .hosts = "hosts",
    .promtail_config = "promtail-config",
    .binary_service = "binary-service",
    .pyroscope_script = "pyroscope-script",
    .pyroscope_service = "pyroscope-service",
    .pyroscope_timer = "pyroscope-timer",
    .docker_tgz = "docker",
    .logrotate_deb = "logrotate",
    .images = &binary_image_urls,
};

test "conformance: generated files match commonware byte for byte" {
    const Case = struct { *const [64]u8, []u8 };
    var no_images = monitoring_urls;
    no_images.images = &.{};
    const targets = [_]services.ScrapeTarget{
        .{ .name = "validator", .ip = "10.0.0.1", .region = "us-east-1", .arch = "arm64" },
        .{ .name = "spammer", .ip = "10.0.0.2", .region = "us-east-1", .arch = "amd64" },
    };
    const worker = .{ "10.0.0.1", "worker", "10.0.1.2", "us-east-1", "arm64" };
    const cases = [_]Case{
        .{
            "8e4ff501d558e6461e254e6a597ea72d5eaaa43ec4816febe26c11309de7e112",
            try output(services.write_install_monitoring_download_cmd, .{&monitoring_urls}),
        },
        .{
            "5fc55fc307184c24ae7cde9bab0455a50048f8f8be1036ea53dfc97b1f5adf19",
            try output(services.write_install_monitoring_download_cmd, .{&no_images}),
        },
        .{
            "74203d0e7fe2a7619522b0de790705dd459fd0a5662b873e5b4ae03c27b70882",
            try output(services.write_install_monitoring_setup_cmd, .{}),
        },
        .{
            "e032b5f967baf69cd7dec44899072a8bd021f27572d688021ef02c2c31d9a09e",
            try output(services.write_start_monitoring_services_cmd, .{}),
        },
        .{
            "21fcfbb281f1af824527ee280a95685a136d2a989dac6cd5157a073041e7a508",
            try output(services.write_install_binary_apt_cmd, .{ true, false }),
        },
        .{
            "4ef85adf1c2bf64346cc13680dc2e16c0e7583fbd1bca964756d8fea1f64a649",
            try output(services.write_install_binary_apt_cmd, .{ false, true }),
        },
        .{
            "84d40c2bf3a0bf55f0ff00247c8cdf57913c9176b461afacac9e24d4107a9f17",
            try output(services.write_install_binary_apt_cmd, .{ true, true }),
        },
        .{
            "e5c509b9b88fbdd76a2caa1d8d7680ed445c44ead7e48fadef28165592ca185f",
            try output(services.write_install_binary_download_cmd, .{&instance_urls}),
        },
        .{
            "3825c2df92026453f6830cf23f3df1c55a010a067958d9fcc6c3e09ea68b8ff9",
            try output(services.write_nvme_setup_cmd, .{}),
        },
        .{
            "24571d86a1bd598fc8399fc1b6eaeced63717642cd1c5dc93c19736d2fc29033",
            try output(services.write_install_binary_setup_cmd, .{true}),
        },
        .{
            "3a98ca5698023f849a05d4c37dc242e3951b4146d7599ffb6d66537b897fb92e",
            try output(services.write_install_binary_setup_cmd, .{false}),
        },
        .{
            "125d23f672c37e1a66f8bdc00351fb6c403f962e9a3487ca595b55b1e136a8de",
            try output(services.write_promtail_config, worker),
        },
        .{
            "0a08790e83cf90869f9d4e6da3154f5855f777cb19303776fa7c9dfc2e407bb2",
            try output(services.write_prometheus_config, .{@as(Targets, &targets)}),
        },
        .{
            "0102b7b7ab24156382795b90074a23d86af7adcfeffb6636dae500fa5bf3317e",
            try output(services.write_prometheus_config, .{@as(Targets, &.{})}),
        },
        .{
            "728ae1f2b0fabec0b7aedb2dc41e541696b4af5e1f6a783dbea04371b8921500",
            try output(services.write_pyroscope_script, worker),
        },
    };
    defer for (cases) |case| gpa.free(case[1]);
    for (cases, 0..) |case, index| {
        expect_sha256(case[0], case[1]) catch |err| {
            std.debug.print("case {d}:\n{s}\n", .{ index, case[1] });
            return err;
        };
    }
    try testing.expect(!try services.write_install_binary_apt_cmd(undefined, false, false));
}

test "conformance: static files match commonware byte for byte" {
    const cases = [_]struct { *const [64]u8, []const u8 }{
        .{
            "87730913e65e812d348ba3da099e18a3f73c7254ae478189f2d04d4937a2ba90",
            services.disable_automatic_apt_upgrades_cmd,
        },
        .{
            "36ecfbf37f56dd956721dc0c6efcfe3ba7fbd656deb8f27601373b7d12bb0aca",
            services.binary_service_unit,
        },
        .{
            "00c1cf6dbf13b943c812b534665871c42035bbe3ef52a5204e5b04729ddd847f",
            services.datasources_yml,
        },
        .{ "2ed88ef6accb8e9c3e92372712e70d450b3277d882ae7d7be01214f6cad12f8d", services.all_yml },
        .{
            "958c6a17a2c8c674af35f840cf75019fbd5631d885df06430cd7bc8accbe88e0",
            services.loki_config,
        },
        .{
            "3967ccea051afcf5f69ee8cee838f4ceb325191dc06cd005d8aa0b4befdde3af",
            services.pyroscope_config,
        },
        .{
            "4dc1dc36177207fdae4e21fee1e271fc88b14f2468b2a1ccba92156f057bec5f",
            services.tempo_config,
        },
        .{
            "0b08c9706070957fdda6ec3ec4bf551e2ec6bb5a8aa8883acc3e798ded25659a",
            services.logrotate_conf,
        },
        .{
            "989b52fc36be1ab4f14ef1f4aa324f903b05ea201b8a3ce4093057d30c806579",
            services.pyroscope_agent_service,
        },
        .{
            "1ef0a7b50b65ad0c58c22ed5f6309576fa25bc9cdde3d905c5ac90117b8ed1f9",
            services.pyroscope_agent_timer,
        },
    };
    for (cases) |case| try expect_sha256(case[0], case[1]);
}

test "disables automatic apt upgrades" {
    const cmd = services.disable_automatic_apt_upgrades_cmd;
    const steps = [_][]const u8{
        "cloud-init status --wait",
        "systemctl mask --now apt-daily.timer apt-daily-upgrade.timer",
        "99-disable-periodic.conf",
        "systemctl show --property=ActiveState --value apt-daily.service",
        "systemctl is-enabled",
        "apt-config shell",
    };
    var previous: usize = 0;
    for (steps) |step| {
        const position = std.mem.indexOf(u8, cmd, step).?;
        try testing.expect(position >= previous);
        previous = position;
    }
    inline for (.{ "Enable", "Update-Package-Lists", "Unattended-Upgrade" }) |setting| {
        try testing.expect(contains(cmd, "APT::Periodic::" ++ setting ++ " \"0\";"));
    }
    try testing.expect(contains(cmd, "fuser -s /var/lib/apt/daily_lock " ++
        "/var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock " ++
        "/var/cache/apt/archives/lock"));
    try testing.expect(!contains(cmd, "fuser -k"));
    // No line stops an apt service: `systemctl`, then `stop`, then the service, in order.
    const stopped = [_][]const u8{
        "apt-daily", "apt-daily.service", "apt-daily-upgrade", "apt-daily-upgrade.service",
    };
    var lines = std.mem.splitScalar(u8, cmd, '\n');
    while (lines.next()) |line| {
        var args = std.mem.tokenizeAny(u8, line, " \t");
        var stage: u8 = 0;
        while (args.next()) |arg| {
            if (stage == 0 and std.mem.eql(u8, arg, "systemctl")) stage = 1;
            if (stage == 1 and std.mem.eql(u8, arg, "stop")) stage = 2;
            if (stage == 2) for (stopped) |service| {
                try testing.expect(!std.mem.eql(u8, arg, service));
            };
        }
    }
}

test "cloud-init wait requires clean completion" {
    var lines = std.mem.splitScalar(u8, services.disable_automatic_apt_upgrades_cmd, '\n');
    const errexit = lines.next().?;
    try testing.expectEqualStrings("set -e", errexit);
    const wait_line = lines.next().?;
    const prefix = "sudo timeout 10m cloud-init status --wait";
    try testing.expect(std.mem.startsWith(u8, wait_line, prefix));
    const wait_suffix = wait_line[prefix.len..];
    const cases = [_]struct { u8, bool }{
        .{ 0, true }, .{ 1, false }, .{ 2, false }, .{ 124, false },
    };
    for (cases) |case| {
        var buffer: [256]u8 = undefined;
        const script = try std.fmt.bufPrint(&buffer, "{s}\nsh -c 'exit {d}'{s}\ntrue", .{
            errexit, case[0], wait_suffix,
        });
        const result = try std.process.run(gpa, testing.io, .{ .argv = &.{ "sh", "-c", script } });
        defer gpa.free(result.stdout);
        defer gpa.free(result.stderr);
        const success = result.term == .exited and result.term.exited == 0;
        try testing.expectEqual(case[1], success);
    }
}

fn expect_written(expected: []const u8, comptime write: anytype, args: anytype) !void {
    const text = try output(write, args);
    defer gpa.free(text);
    try testing.expectEqualStrings(expected, text);
}

test "binary s3 keys arm64" {
    const arch: Architecture = .arm64;
    try expect_written(
        "tools/binaries/docker/29.6.0/linux-aarch64/docker-29.6.0.tgz",
        services.write_docker_bin_s3_key,
        .{ "29.6.0", arch },
    );
    try expect_written(
        "tools/binaries/samply/0.13.1/linux-aarch64/samply-aarch64-unknown-linux-gnu.tar.xz",
        services.write_samply_bin_s3_key,
        .{ "0.13.1", arch },
    );
    try expect_written(
        "tools/binaries/logrotate/3.21.0-2build1/linux-arm64/logrotate_3.21.0-2build1_arm64.deb",
        services.write_logrotate_bin_s3_key,
        .{ "3.21.0-2build1", arch },
    );
}

test "binary s3 keys x86_64" {
    const arch: Architecture = .x86_64;
    try expect_written(
        "tools/binaries/docker/29.6.0/linux-x86_64/docker-29.6.0.tgz",
        services.write_docker_bin_s3_key,
        .{ "29.6.0", arch },
    );
    try expect_written(
        "tools/binaries/samply/0.13.1/linux-x86_64/samply-x86_64-unknown-linux-gnu.tar.xz",
        services.write_samply_bin_s3_key,
        .{ "0.13.1", arch },
    );
    try expect_written(
        "tools/binaries/logrotate/3.21.0-2build1/linux-amd64/logrotate_3.21.0-2build1_amd64.deb",
        services.write_logrotate_bin_s3_key,
        .{ "3.21.0-2build1", arch },
    );
}

test "image keys, file names, and download urls" {
    try expect_written(
        "tools/binaries/images/prom_prometheus_v3.2.0/linux-arm64/image.tar.gz",
        services.write_image_s3_key,
        .{ services.prometheus_image, Architecture.arm64 },
    );
    try expect_written(
        "tools/binaries/images/prom_prometheus_v3.2.0/linux-amd64/image.tar.gz",
        services.write_image_s3_key,
        .{ services.prometheus_image, Architecture.x86_64 },
    );
    var buffer: [64]u8 = undefined;
    try testing.expectEqualStrings(
        "ghcr.io_clabby_tracer-web_0.2.1.tar.gz",
        try image_file_name(&buffer, services.tracer_image),
    );
    try expect_written(
        "https://github.com/mstange/samply/releases/download/samply-v0.13.1/" ++
            "samply-aarch64-unknown-linux-gnu.tar.xz",
        services.write_samply_download_url,
        .{ "0.13.1", Architecture.arm64 },
    );
    try expect_written(
        "https://download.docker.com/linux/static/stable/x86_64/docker-29.6.0.tgz",
        services.write_docker_download_url,
        .{ "29.6.0", Architecture.x86_64 },
    );
    try expect_written(
        "http://ports.ubuntu.com/ubuntu-ports/pool/main/l/logrotate/" ++
            "logrotate_3.21.0-2build1_arm64.deb",
        services.write_logrotate_download_url,
        .{ "3.21.0-2build1", Architecture.arm64 },
    );
    try expect_written(
        "http://archive.ubuntu.com/ubuntu/pool/main/l/logrotate/" ++
            "logrotate_3.21.0-2build1_amd64.deb",
        services.write_logrotate_download_url,
        .{ "3.21.0-2build1", Architecture.x86_64 },
    );
    try expect_written(
        "https://grafana.com/api/dashboards/1860/revisions/45/download",
        services.write_grafana_node_exporter_dashboard_download_url,
        .{services.grafana_node_exporter_dashboard_version},
    );
    // commonware's distinct images, in first-use order.
    const monitoring = [_][]const u8{
        "prom/node-exporter:v1.9.0",       "prom/prometheus:v3.2.0", "grafana/loki:3.4.2",
        "grafana/pyroscope:1.12.0",        "grafana/tempo:2.7.1",    "grafana/grafana:11.5.2",
        "ghcr.io/clabby/tracer-web:0.2.1",
    };
    try testing.expectEqual(monitoring.len, services.monitoring_images.len);
    for (monitoring, services.monitoring_images) |want, got| {
        try testing.expectEqualStrings(want, got);
    }
    try testing.expectEqual(@as(usize, 2), services.binary_images.len);
    try testing.expectEqualStrings("grafana/promtail:3.4.2", services.binary_images[0]);
}

test "config s3 keys" {
    const prefix = "tools/configs/" ++ services.deployer_version;
    try testing.expectEqualStrings(
        prefix ++ "/grafana/datasources.yml",
        services.grafana_datasources_s3_key,
    );
    try testing.expectEqualStrings(
        prefix ++ "/grafana/all.yml",
        services.grafana_dashboards_s3_key,
    );
    try expect_written(
        prefix ++ "/grafana/node-exporter-full-revision-45.json",
        services.write_grafana_node_exporter_dashboard_s3_key,
        .{services.grafana_node_exporter_dashboard_version},
    );
    try testing.expectEqualStrings(prefix ++ "/loki/config.yml", services.loki_config_s3_key);
    try testing.expectEqualStrings(
        prefix ++ "/pyroscope/config.yml",
        services.pyroscope_config_s3_key,
    );
    try testing.expectEqualStrings(prefix ++ "/tempo/config.yml", services.tempo_config_s3_key);
    try testing.expectEqualStrings(
        prefix ++ "/pyroscope/agent.service",
        services.pyroscope_agent_service_s3_key,
    );
    try testing.expectEqualStrings(
        prefix ++ "/pyroscope/agent.timer",
        services.pyroscope_agent_timer_s3_key,
    );
    try testing.expectEqualStrings(
        prefix ++ "/binary/service-arm64",
        services.binary_service_s3_key_for_arch(.arm64),
    );
    try testing.expectEqualStrings(
        prefix ++ "/binary/service-amd64",
        services.binary_service_s3_key_for_arch(.x86_64),
    );
}

test "monitoring installs node exporter dashboard" {
    const download = try output(write_monitoring_download, .{&monitoring_urls});
    defer gpa.free(download);
    try testing.expect(contains(download, "-O " ++ home ++ "/docker.tgz"));
    try testing.expect(contains(download, "-O " ++ home ++ "/node-exporter-full.json"));
    try testing.expect(contains(download, "node-exporter-dashboard"));

    const setup = try output(services.write_install_monitoring_setup_cmd, .{});
    defer gpa.free(setup);
    try testing.expect(contains(setup, "sudo mv " ++ home ++
        "/dashboard.json /var/lib/grafana/dashboards/dashboard.json"));
    try testing.expect(contains(setup, "sudo mv " ++ home ++
        "/node-exporter-full.json /var/lib/grafana/dashboards/node-exporter-full.json"));
}

test "monitoring installs image services" {
    var name: [64]u8 = undefined;
    const download = try output(write_monitoring_download, .{&monitoring_urls});
    defer gpa.free(download);
    for ([_][]const u8{
        "tracer.service", "prometheus.tar.gz", "grafana.deb", "node_exporter.tar.gz",
    }) |absent| try testing.expect(!contains(download, absent));
    var line: [128]u8 = undefined;
    for ([_][]const u8{ services.tracer_image, services.prometheus_image }) |image| {
        const file = try image_file_name(&name, image);
        const flag = try std.fmt.bufPrint(&line, "-O {s}/images/{s}", .{ home, file });
        try testing.expect(contains(download, flag));
    }

    const setup = try output(services.write_install_monitoring_setup_cmd, .{});
    defer gpa.free(setup);
    for ([_][]const u8{
        "# Install Docker services",
        "tar xzf " ++ home ++ "/docker.tgz -C " ++ home,
        "ExecStart=/usr/local/bin/dockerd --host=unix:///var/run/docker.sock",
        "ExecStartPre=-/usr/local/bin/docker rm -f tracer",
        "ExecStart=/usr/local/bin/docker run --rm --name tracer",
        "sudo tee /etc/systemd/system/tracer.service",
        "sudo tee /etc/systemd/system/grafana.service",
        "--env TEMPO_URL=http://127.0.0.1:3200 " ++ services.tracer_image,
        "--network host",
        "--volume /tempo:/var/tempo",
    }) |present| try testing.expect(contains(setup, present));
    for ([_][]const u8{
        "/usr/bin/docker",        "apt-get install -y docker.io", "docker pull", "docker login",
        "--volume /tempo:/tempo",
    }) |absent| try testing.expect(!contains(setup, absent));
    for (services.monitoring_images) |image| {
        const file = try image_file_name(&name, image);
        const load = try std.fmt.bufPrint(&line, load_format, .{ home, file });
        try testing.expect(contains(setup, load));
        const remove = try std.fmt.bufPrint(&line, "sudo rm -f {s}/images/{s}", .{ home, file });
        try testing.expect(contains(setup, remove));
    }

    const start = try output(services.write_start_monitoring_services_cmd, .{});
    defer gpa.free(start);
    for (services.monitoring_image_service_names) |service| {
        const start_line = try std.fmt.bufPrint(&line, "sudo systemctl start {s}", .{service});
        try testing.expect(contains(start, start_line));
        const enable_line = try std.fmt.bufPrint(&line, "sudo systemctl enable {s}", .{service});
        try testing.expect(contains(start, enable_line));
    }

    const tempo = services.tempo_config;
    try testing.expect(contains(tempo, "path: /var/tempo/traces"));
    try testing.expect(contains(tempo, "path: /var/tempo/wal"));
    try testing.expect(contains(tempo, "grpc_server_max_recv_msg_size: 104857600"));
    try testing.expect(contains(tempo, "grpc_server_max_send_msg_size: 104857600"));
    try testing.expect(!contains(tempo, "path: /tempo/"));
}

test "prometheus config scrapes binary metrics for all instances" {
    const targets = [_]services.ScrapeTarget{
        .{ .name = "validator", .ip = "10.0.0.1", .region = "us-east-1", .arch = "arm64" },
        .{ .name = "spammer", .ip = "10.0.0.2", .region = "us-east-1", .arch = "arm64" },
    };
    const config = try output(
        services.write_prometheus_config,
        .{@as([]const services.ScrapeTarget, &targets)},
    );
    defer gpa.free(config);
    for ([_][]const u8{
        "job_name: 'validator_binary'", "targets: ['10.0.0.1:9090']",
        "job_name: 'validator_system'", "targets: ['10.0.0.1:9100']",
        "job_name: 'spammer_binary'",   "targets: ['10.0.0.2:9090']",
        "job_name: 'spammer_system'",   "targets: ['10.0.0.2:9100']",
    }) |present| try testing.expect(contains(config, present));
}

test "binary installs image helpers" {
    var name: [64]u8 = undefined;
    var line: [128]u8 = undefined;
    const download = try output(services.write_install_binary_download_cmd, .{&instance_urls});
    defer gpa.free(download);
    for ([_][]const u8{ "/promtail.yml", "/docker.tgz", "/logrotate.deb" }) |file| {
        const flag = try std.fmt.bufPrint(&line, "-O {s}{s}", .{ home, file });
        try testing.expect(contains(download, flag));
    }
    const setup = try output(services.write_install_binary_setup_cmd, .{false});
    defer gpa.free(setup);
    for ([_][]const u8{ services.promtail_image, services.node_exporter_image }) |image| {
        const file = try image_file_name(&name, image);
        const flag = try std.fmt.bufPrint(&line, "-O {s}/images/{s}", .{ home, file });
        try testing.expect(contains(download, flag));
        const load = try std.fmt.bufPrint(&line, load_format, .{ home, file });
        try testing.expect(contains(setup, load));
    }
    for ([_][]const u8{
        "sudo tee /etc/systemd/system/promtail.service",
        "sudo tee /etc/systemd/system/node_exporter.service",
        "ExecStartPre=-/usr/local/bin/docker rm -f promtail",
        "ExecStart=/usr/local/bin/docker run --rm --name promtail",
        "sudo dpkg -i " ++ home ++ "/logrotate.deb",
        "copytruncate",
        "echo \"0 * * * * /usr/sbin/logrotate /etc/logrotate.d/binary\" | crontab -",
        "sudo systemctl enable node_exporter",
        "sudo systemctl enable promtail",
        "sudo systemctl enable binary",
        "tc qdisc replace dev \"$IFACE\" root handle 1: mq",
        "tc qdisc replace dev \"$IFACE\" root fq",
        "sudo systemctl enable --now setup-qdisc.service",
        "net.ipv4.tcp_rmem=4096 2097152 16777216",
    }) |present| try testing.expect(contains(setup, present));
    for ([_][]const u8{
        "docker pull", "docker login", "/usr/bin/docker", "binary-log-truncate", "busybox",
    }) |absent| try testing.expect(!contains(setup, absent));
    const binary_start = std.mem.indexOf(u8, setup, "sudo systemctl start binary || true").?;
    const node_exporter_start = std.mem.indexOf(u8, setup, "sudo systemctl start node_exporter").?;
    const promtail_start = std.mem.indexOf(u8, setup, "sudo systemctl start promtail").?;
    try testing.expect(node_exporter_start < binary_start);
    try testing.expect(promtail_start < binary_start);

    const promtail = try output(
        services.write_promtail_config,
        .{ "10.0.0.1", "worker", "10.0.1.2", "us-east-1", "arm64" },
    );
    defer gpa.free(promtail);
    try testing.expect(contains(promtail, "filename: /var/lib/promtail/positions.yaml"));
}

test "deployment s3 keys" {
    const digest = "abc123def456";
    const cases = [_]struct { services.DeploymentFile, []const u8 }{
        .{ .binaries, "deployments/my-tag/binaries/abc123def456" },
        .{ .configs, "deployments/my-tag/configs/abc123def456" },
        .{ .hosts, "deployments/my-tag/hosts/abc123def456" },
        .{ .promtail, "deployments/my-tag/promtail/abc123def456" },
        .{ .pyroscope, "deployments/my-tag/pyroscope/abc123def456" },
        .{ .monitoring, "deployments/my-tag/monitoring/abc123def456" },
    };
    for (cases) |case| {
        const args = .{ "my-tag", case[0], digest };
        try expect_written(case[1], services.write_deployment_s3_key, args);
    }
}
