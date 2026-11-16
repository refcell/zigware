//! Service configuration for Prometheus, Loki, Grafana, Promtail, Tempo, Pyroscope, the
//! tracer, and the caller-provided binary (commonware `deployer::aws::services`).
//!
//! Every generated script, unit, and config is byte-identical to commonware's, checked with
//! SHA-256 conformance hashes of commonware's output. The templates below are commonware's raw
//! strings verbatim, rendered by `render` with Rust's `format!` syntax (`{name}`, `{{`, `}}`),
//! except that the home directory is written `<home>` and filled in by `expand` at comptime.

const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;
const Architecture = @import("mod.zig").Architecture;
const s3 = @import("s3.zig");

pub const WriteError = Io.Writer.Error;

/// Binary artifacts and user SSH state live here. NVMe-backed instances mount instance-store
/// storage here, so binary configs use NVMe without extra configuration.
pub const home_directory = "/" ++ "home/ubuntu";

/// Install path of the Docker static binary.
const docker_bin = "/usr/local/bin/docker";

/// Deployer version namespacing static configs in S3: commonware's, so both share a cache.
pub const deployer_version = "2026.10.0";

/// Version of the Grafana Node Exporter Full dashboard to provision
/// (https://grafana.com/grafana/dashboards/1860-node-exporter-full/).
pub const grafana_node_exporter_dashboard_version = "45";
/// Version of Docker static binaries to download and install.
pub const docker_version = "29.6.0";
/// Version of Samply to download and install.
pub const samply_version = "0.13.1";
/// Version of the logrotate package for Ubuntu 24.04.
pub const logrotate_version = "3.21.0-2build1";

const ubuntu_archive_arm64 = "http://ports.ubuntu.com/ubuntu-ports/pool";
const ubuntu_archive_x86_64 = "http://archive.ubuntu.com/ubuntu/pool";

pub const prometheus_image = "prom/prometheus:v3.2.0";
pub const promtail_image = "grafana/promtail:3.4.2";
pub const node_exporter_image = "prom/node-exporter:v1.9.0";
pub const loki_image = "grafana/loki:3.4.2";
pub const tempo_image = "grafana/tempo:2.7.1";
pub const pyroscope_image = "grafana/pyroscope:1.12.0";
pub const grafana_image = "grafana/grafana:11.5.2";
pub const tracer_image = "ghcr.io/clabby/tracer-web:0.2.1";

// --- Templates ---------------------------------------------------------------------------------

/// `text` with every `<home>` replaced by `home_directory`.
inline fn expand(comptime text: []const u8) []const u8 {
    comptime {
        @setEvalBranchQuota(200_000);
        const size = std.mem.replacementSize(u8, text, "<home>", home_directory);
        var out: [size]u8 = undefined;
        _ = std.mem.replace(u8, text, "<home>", home_directory, &out);
        const final = out;
        return &final;
    }
}

const Segment = struct { text: []const u8, name: ?[]const u8 };

/// Splits a `format!` template into literal text, each followed by an optional argument.
fn parse_template(comptime template: []const u8) []const Segment {
    comptime {
        @setEvalBranchQuota(200_000);
        var segments: []const Segment = &.{};
        var start = 0;
        var index = 0;
        while (index < template.len) {
            const char = template[index];
            if (char != '{' and char != '}') {
                index += 1;
                continue;
            }
            if (index + 1 < template.len and template[index + 1] == char) {
                // `{{` or `}}`: keep one brace and skip the other.
                const literal: Segment = .{ .text = template[start .. index + 1], .name = null };
                segments = segments ++ .{literal};
                start = index + 2;
                index += 2;
                continue;
            }
            if (char == '}') @compileError("unmatched } in template");
            const end = std.mem.indexOfScalarPos(u8, template, index, '}') orelse
                @compileError("unclosed { in template");
            const name = template[index + 1 .. end];
            segments = segments ++ .{Segment{ .text = template[start..index], .name = name }};
            start = end + 1;
            index = end + 1;
        }
        segments = segments ++ .{Segment{ .text = template[start..], .name = null }};
        const final = segments[0..segments.len].*;
        return &final;
    }
}

/// Writes `template` with each `{name}` replaced by `args.name`: a string, or a value with a
/// `write(*Io.Writer)` method.
fn render(writer: *Io.Writer, comptime template: []const u8, args: anytype) WriteError!void {
    const segments = comptime parse_template(template);
    inline for (segments) |segment| {
        try writer.writeAll(segment.text);
        if (segment.name) |name| {
            const value = @field(args, name);
            if (comptime std.meta.hasMethod(@TypeOf(value), "write")) {
                try value.write(writer);
            } else {
                try writer.writeAll(value);
            }
        }
    }
}

/// `prefix`, then `words` separated by spaces (with `leading`, a space before each word).
const Words = struct {
    prefix: []const u8 = "",
    words: []const []const u8,
    leading: bool = true,

    pub fn write(words: Words, writer: *Io.Writer) WriteError!void {
        try writer.writeAll(words.prefix);
        for (words.words, 0..) |word, index| {
            if (words.leading or index > 0) try writer.writeByte(' ');
            try writer.writeAll(word);
        }
    }
};

// --- Image services ----------------------------------------------------------------------------

/// A container image run as a systemd service.
const ImageService = struct {
    service: []const u8,
    description: []const u8,
    image: []const u8,
    network_host: bool = true,
    pid_host: bool = false,
    user: ?[]const u8 = "0:0",
    env: []const [2][]const u8 = &.{},
    volumes: []const []const u8 = &.{},
    args: []const []const u8 = &.{},
    options: []const []const u8 = &.{},
    after: []const []const u8 = &.{},

    /// The ` --network host ...` options of `docker run`.
    pub fn write(service: *const ImageService, writer: *Io.Writer) WriteError!void {
        if (service.network_host) try writer.writeAll(" --network host");
        if (service.pid_host) try writer.writeAll(" --pid host");
        if (service.user) |user| try writer.print(" --user {s}", .{user});
        for (service.env) |pair| try writer.print(" --env {s}={s}", .{ pair[0], pair[1] });
        for (service.volumes) |volume| try writer.print(" --volume {s}", .{volume});
        for (service.options) |option| try writer.print(" {s}", .{option});
    }

    fn write_service_file(service: *const ImageService, writer: *Io.Writer) WriteError!void {
        assert(service.service.len > 0);
        assert(service.image.len > 0);
        try render(writer, service_file_template, .{
            .description = service.description,
            .after_line = Words{
                .prefix = "After=network-online.target docker.service",
                .words = service.after,
            },
            .docker_bin = docker_bin,
            .service = service.service,
            .run_options = service,
            .image = service.image,
            .args = Words{ .words = service.args },
        });
    }
};

const node_exporter_args = [_][]const u8{
    "--path.procfs=/host/proc",
    "--path.sysfs=/host/sys",
    "--path.rootfs=/host/rootfs",
    "--collector.filesystem.mount-points-exclude=" ++
        "^/(dev|proc|sys|var/lib/docker/.+|var/lib/containers/.+)($|/)",
};

const node_exporter_volumes = [_][]const u8{
    "/proc:/host/proc:ro",
    "/sys:/host/sys:ro",
    "/:/host/rootfs:ro,rslave",
};

const node_exporter: ImageService = .{
    .service = "node_exporter",
    .description = "Node Exporter",
    .image = node_exporter_image,
    .pid_host = true,
    .volumes = &node_exporter_volumes,
    .args = &node_exporter_args,
};

const monitoring_image_services = [_]ImageService{
    node_exporter,
    .{
        .service = "prometheus",
        .description = "Prometheus Monitoring Service",
        .image = prometheus_image,
        .volumes = &.{
            "/opt/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro",
            "/opt/prometheus/data:/prometheus",
        },
        .args = &.{
            "--config.file=/etc/prometheus/prometheus.yml",
            "--storage.tsdb.path=/prometheus",
        },
        .after = &.{"node_exporter.service"},
    },
    .{
        .service = "loki",
        .description = "Loki Log Aggregation Service",
        .image = loki_image,
        .volumes = &.{ "/etc/loki/loki.yml:/etc/loki/loki.yml:ro", "/loki:/loki" },
        .args = &.{"-config.file=/etc/loki/loki.yml"},
    },
    .{
        .service = "pyroscope",
        .description = "Pyroscope Profiling Service",
        .image = pyroscope_image,
        .volumes = &.{
            "/etc/pyroscope/pyroscope.yml:/etc/pyroscope/pyroscope.yml:ro",
            "/var/lib/pyroscope:/var/lib/pyroscope",
        },
        .args = &.{"--config.file=/etc/pyroscope/pyroscope.yml"},
    },
    .{
        .service = "tempo",
        .description = "Tempo Tracing Service",
        .image = tempo_image,
        .volumes = &.{ "/etc/tempo/tempo.yml:/etc/tempo/tempo.yml:ro", "/tempo:/var/tempo" },
        .args = &.{"-config.file=/etc/tempo/tempo.yml"},
    },
    .{
        .service = "grafana",
        .description = "Grafana Dashboard Service",
        .image = grafana_image,
        .env = &.{
            .{ "GF_AUTH_ANONYMOUS_ENABLED", "true" },
            .{ "GF_AUTH_ANONYMOUS_ORG_ROLE", "Admin" },
            .{ "GF_INSTALL_PLUGINS", "grafana-pyroscope-app" },
        },
        .volumes = &.{
            "/etc/grafana/provisioning:/etc/grafana/provisioning:ro",
            "/var/lib/grafana:/var/lib/grafana",
        },
        .after = &.{ "prometheus.service", "loki.service", "tempo.service", "pyroscope.service" },
    },
    .{
        .service = "tracer",
        .description = "Tracer Trace Viewer",
        .image = tracer_image,
        .user = null,
        .env = &.{.{ "TEMPO_URL", "http://127.0.0.1:3200" }},
        .after = &.{"tempo.service"},
    },
};

const binary_image_services = [_]ImageService{
    .{
        .service = "promtail",
        .description = "Promtail Log Forwarder",
        .image = promtail_image,
        .volumes = &.{
            "/etc/promtail:/etc/promtail:ro",
            "/var/log:/var/log:ro",
            "/var/lib/promtail:/var/lib/promtail",
        },
        .args = &.{"-config.file=/etc/promtail/promtail.yml"},
        .after = &.{"binary.service"},
    },
    node_exporter,
};

fn distinct_images(comptime services: []const ImageService) []const []const u8 {
    comptime {
        var images: []const []const u8 = &.{};
        for (services) |service| {
            for (images) |image| {
                if (std.mem.eql(u8, image, service.image)) break;
            } else images = images ++ .{service.image};
        }
        const final = images[0..images.len].*;
        return &final;
    }
}

fn service_names(comptime services: []const ImageService) []const []const u8 {
    comptime {
        var names: [services.len][]const u8 = undefined;
        for (services, &names) |service, *name| name.* = service.service;
        const final = names;
        return &final;
    }
}

/// The distinct images the monitoring instance runs.
pub const monitoring_images = distinct_images(&monitoring_image_services);
/// The distinct images binary instances run.
pub const binary_images = distinct_images(&binary_image_services);
/// The systemd services of the monitoring instance's images.
pub const monitoring_image_service_names = service_names(&monitoring_image_services);
/// The systemd services of binary instances' images.
pub const binary_image_service_names = service_names(&binary_image_services);

/// Writes `image` as a filesystem- and S3-safe token (`prom/prometheus:v3.2.0` becomes
/// `prom_prometheus_v3.2.0`).
pub fn write_sanitized_image(writer: *Io.Writer, image: []const u8) WriteError!void {
    assert(image.len > 0);
    for (image) |byte| try writer.writeByte(if (byte == '/' or byte == ':') '_' else byte);
}

/// The on-instance file name of an image tarball (`{sanitized}.tar.gz`).
pub fn write_image_file_name(writer: *Io.Writer, image: []const u8) WriteError!void {
    try write_sanitized_image(writer, image);
    try writer.writeAll(".tar.gz");
}

// --- S3 keys and download URLs -----------------------------------------------------------------

/// The architecture name in Docker, Samply, and kernel (`uname -m`) terms.
fn machine(architecture: Architecture) []const u8 {
    return switch (architecture) {
        .arm64 => "aarch64",
        .x86_64 => "x86_64",
    };
}

/// The S3 key of a cached image tarball (`docker save` output, per architecture).
pub fn write_image_s3_key(
    writer: *Io.Writer,
    image: []const u8,
    architecture: Architecture,
) WriteError!void {
    try writer.writeAll(s3.tools_binaries_prefix ++ "/images/");
    try write_sanitized_image(writer, image);
    try writer.print("/linux-{s}/image.tar.gz", .{architecture.as_str()});
}

pub fn write_docker_bin_s3_key(
    writer: *Io.Writer,
    version: []const u8,
    architecture: Architecture,
) WriteError!void {
    const arch = machine(architecture);
    try writer.print(s3.tools_binaries_prefix ++ "/docker/{s}/linux-{s}/docker-{s}.tgz", .{
        version, arch, version,
    });
}

pub fn write_samply_bin_s3_key(
    writer: *Io.Writer,
    version: []const u8,
    architecture: Architecture,
) WriteError!void {
    const arch = machine(architecture);
    try writer.print(
        s3.tools_binaries_prefix ++ "/samply/{s}/linux-{s}/samply-{s}-unknown-linux-gnu.tar.xz",
        .{ version, arch, arch },
    );
}

pub fn write_logrotate_bin_s3_key(
    writer: *Io.Writer,
    version: []const u8,
    architecture: Architecture,
) WriteError!void {
    const arch = architecture.as_str();
    const path = s3.tools_binaries_prefix ++ "/logrotate/{s}/linux-{s}/logrotate_{s}_{s}.deb";
    try writer.print(path, .{
        version, arch, version, arch,
    });
}

/// Static configs and services: `{tools_configs_prefix}/{deployer_version}/{component}/{file}`.
const configs = s3.tools_configs_prefix ++ "/" ++ deployer_version;
pub const grafana_datasources_s3_key = configs ++ "/grafana/datasources.yml";
pub const grafana_dashboards_s3_key = configs ++ "/grafana/all.yml";
pub const loki_config_s3_key = configs ++ "/loki/config.yml";
pub const pyroscope_config_s3_key = configs ++ "/pyroscope/config.yml";
pub const tempo_config_s3_key = configs ++ "/tempo/config.yml";
pub const pyroscope_agent_service_s3_key = configs ++ "/pyroscope/agent.service";
pub const pyroscope_agent_timer_s3_key = configs ++ "/pyroscope/agent.timer";

pub fn write_grafana_node_exporter_dashboard_s3_key(
    writer: *Io.Writer,
    version: []const u8,
) WriteError!void {
    try writer.print(configs ++ "/grafana/node-exporter-full-revision-{s}.json", .{version});
}

/// The S3 key of the binary's systemd unit for `architecture`.
pub fn binary_service_s3_key_for_arch(architecture: Architecture) []const u8 {
    return switch (architecture) {
        .arm64 => configs ++ "/binary/service-arm64",
        .x86_64 => configs ++ "/binary/service-amd64",
    };
}

/// Kinds of per-deployment files, deduplicated by content digest within a deployment.
pub const DeploymentFile = enum {
    binaries,
    configs,
    hosts,
    promtail,
    pyroscope,
    monitoring,
};

/// `deployments/{tag}/{kind}/{digest}`.
pub fn write_deployment_s3_key(
    writer: *Io.Writer,
    tag: []const u8,
    kind: DeploymentFile,
    digest: []const u8,
) WriteError!void {
    assert(tag.len > 0);
    assert(digest.len > 0);
    try writer.print(s3.deployments_prefix ++ "/{s}/{t}/{s}", .{ tag, kind, digest });
}

pub fn write_grafana_node_exporter_dashboard_download_url(
    writer: *Io.Writer,
    version: []const u8,
) WriteError!void {
    try writer.print("https://grafana.com/api/dashboards/1860/revisions/{s}/download", .{version});
}

pub fn write_samply_download_url(
    writer: *Io.Writer,
    version: []const u8,
    architecture: Architecture,
) WriteError!void {
    const arch = machine(architecture);
    try writer.print(
        "https://github.com/mstange/samply/releases/download/samply-v{s}/" ++
            "samply-{s}-unknown-linux-gnu.tar.xz",
        .{ version, arch },
    );
}

pub fn write_docker_download_url(
    writer: *Io.Writer,
    version: []const u8,
    architecture: Architecture,
) WriteError!void {
    try writer.print("https://download.docker.com/linux/static/stable/{s}/docker-{s}.tgz", .{
        machine(architecture), version,
    });
}

pub fn write_logrotate_download_url(
    writer: *Io.Writer,
    version: []const u8,
    architecture: Architecture,
) WriteError!void {
    const base = switch (architecture) {
        .arm64 => ubuntu_archive_arm64,
        .x86_64 => ubuntu_archive_x86_64,
    };
    const arch = architecture.as_str();
    try writer.print("{s}/main/l/logrotate/logrotate_{s}_{s}.deb", .{ base, version, arch });
}

// --- Install commands --------------------------------------------------------------------------

/// A presigned URL for an image tarball.
pub const ImageUrl = struct { image: []const u8, url: []const u8 };

/// URLs for monitoring service installation.
pub const MonitoringUrls = struct {
    docker_tgz: []const u8,
    prometheus_config: []const u8,
    datasources_yml: []const u8,
    all_yml: []const u8,
    dashboard: []const u8,
    node_exporter_dashboard: []const u8,
    loki_yml: []const u8,
    pyroscope_yml: []const u8,
    tempo_yml: []const u8,
    images: []const ImageUrl,
};

/// URLs for binary instance installation.
pub const InstanceUrls = struct {
    binary: []const u8,
    config: []const u8,
    hosts: []const u8,
    promtail_config: []const u8,
    binary_service: []const u8,
    pyroscope_script: []const u8,
    pyroscope_service: []const u8,
    pyroscope_timer: []const u8,
    docker_tgz: []const u8,
    logrotate_deb: []const u8,
    images: []const ImageUrl,
};

/// Downloads and verifies the per-architecture image tarballs concurrently.
fn write_image_download_block(writer: *Io.Writer, images: []const ImageUrl) WriteError!void {
    if (images.len == 0) return;
    try writer.writeAll(expand("\n# Download container image tarballs from S3 concurrently via " ++
        "pre-signed URLs\nmkdir -p <home>/images\nrm -f <home>/images/*.tar.gz\n"));
    for (images) |entry| {
        try writer.writeAll(s3.wget ++ expand(" -O <home>/images/"));
        try write_image_file_name(writer, entry.image);
        try writer.print(" '{s}' &\n", .{entry.url});
    }
    try writer.writeAll("wait\nfor f in");
    for (images) |entry| {
        try writer.writeByte(' ');
        try write_image_file_name(writer, entry.image);
    }
    try writer.writeAll(expand("; do\n    if [ ! -s \"<home>/images/$f\" ]; then\n" ++
        "        echo \"ERROR: Failed to download image $f\" >&2\n        exit 1\n    fi\ndone\n"));
}

/// Phase 1 on the monitoring instance: download files from S3.
pub fn write_install_monitoring_download_cmd(
    writer: *Io.Writer,
    urls: *const MonitoringUrls,
) WriteError!void {
    try render(writer, monitoring_download_template, .{
        .WGET = s3.wget,
        .docker_tgz = urls.docker_tgz,
        .prometheus_config = urls.prometheus_config,
        .datasources_yml = urls.datasources_yml,
        .all_yml = urls.all_yml,
        .dashboard = urls.dashboard,
        .node_exporter_dashboard = urls.node_exporter_dashboard,
        .loki_yml = urls.loki_yml,
        .pyroscope_yml = urls.pyroscope_yml,
        .tempo_yml = urls.tempo_yml,
    });
    try write_image_download_block(writer, urls.images);
}

/// Installs Docker, loads each image (deleting its tarball so the layers and the archive do not
/// both fill the small root volume), and writes each service's unit.
const ImageServices = struct {
    services: []const ImageService,

    pub fn write(image_services: ImageServices, writer: *Io.Writer) WriteError!void {
        const services = image_services.services;
        assert(services.len > 0);
        try writer.writeAll(image_services_head);
        for (services, 0..) |service, index| {
            // `distinct_images`: skip an image an earlier service already loaded.
            const seen = for (services[0..index]) |earlier| {
                if (std.mem.eql(u8, earlier.image, service.image)) break true;
            } else false;
            if (seen) continue;
            inline for (.{ "sudo docker load -i ", "sudo rm -f " }) |command| {
                try writer.writeAll(command ++ expand("<home>/images/"));
                try write_image_file_name(writer, service.image);
                try writer.writeByte('\n');
            }
        }
        for (services) |*service| {
            try writer.print("sudo tee /etc/systemd/system/{s}.service >/dev/null <<'EOF'\n", .{
                service.service,
            });
            try service.write_service_file(writer);
            try writer.writeAll("EOF\n");
        }
    }
};

/// Phase 2 on the monitoring instance: set up services (without starting them).
pub fn write_install_monitoring_setup_cmd(writer: *Io.Writer) WriteError!void {
    try render(writer, monitoring_setup_template, .{
        .image_services = ImageServices{ .services = &monitoring_image_services },
    });
}

/// Phase 3 on the monitoring instance: start and enable its services.
pub fn write_start_monitoring_services_cmd(writer: *Io.Writer) WriteError!void {
    try writer.writeAll(start_monitoring_head);
    for (monitoring_image_service_names) |service| {
        try writer.print("sudo systemctl start {s}\n", .{service});
        try writer.print("sudo systemctl enable {s}\n", .{service});
    }
}

/// Phase 1 on binary instances, needed only when profiling or mounting NVMe instance storage:
/// installs apt packages. Returns false, writing nothing, when no package is needed.
pub fn write_install_binary_apt_cmd(
    writer: *Io.Writer,
    profiling: bool,
    nvme: bool,
) WriteError!bool {
    const profiling_packages = [_][]const u8{
        "linux-tools-common", "linux-tools-generic", "linux-tools-$(uname -r)",
    };
    var packages: [profiling_packages.len + 1][]const u8 = undefined;
    var count: usize = 0;
    if (profiling) {
        packages[0..profiling_packages.len].* = profiling_packages;
        count = profiling_packages.len;
    }
    if (nvme) {
        packages[count] = "mdadm";
        count += 1;
    }
    if (count == 0) return false;
    try render(writer, apt_template, .{
        .packages = Words{ .words = packages[0..count], .leading = false },
    });
    return true;
}

/// Phase 2 on binary instances: download files from S3.
pub fn write_install_binary_download_cmd(
    writer: *Io.Writer,
    urls: *const InstanceUrls,
) WriteError!void {
    try render(writer, binary_download_template, .{
        .WGET = s3.wget,
        .binary = urls.binary,
        .config = urls.config,
        .hosts = urls.hosts,
        .promtail_config = urls.promtail_config,
        .binary_service = urls.binary_service,
        .pyroscope_script = urls.pyroscope_script,
        .pyroscope_service = urls.pyroscope_service,
        .pyroscope_timer = urls.pyroscope_timer,
        .docker_tgz = urls.docker_tgz,
        .logrotate_deb = urls.logrotate_deb,
    });
    try write_image_download_block(writer, urls.images);
}

/// Mounts EC2 NVMe instance-store storage at the binary's working directory.
pub fn write_nvme_setup_cmd(writer: *Io.Writer) WriteError!void {
    try render(writer, nvme_setup_template, .{ .mount_directory = home_directory });
}

/// Phase 3 on binary instances: set up and start services.
pub fn write_install_binary_setup_cmd(writer: *Io.Writer, profiling: bool) WriteError!void {
    const perf: []const u8 = if (profiling) perf_setup else "";
    const pyroscope_enable: []const u8 =
        if (profiling) "\nsudo systemctl enable --now pyroscope-agent.timer\n" else "";
    try render(writer, binary_setup_template, .{
        .image_services = ImageServices{ .services = &binary_image_services },
        .LOGROTATE_CONF = logrotate_conf,
        .perf_setup = perf,
        .pyroscope_enable = pyroscope_enable,
    });
}

/// Promtail configuration pushing the binary's logs to the monitoring instance.
pub fn write_promtail_config(
    writer: *Io.Writer,
    monitoring_private_ip: []const u8,
    instance_name: []const u8,
    ip: []const u8,
    region: []const u8,
    arch: []const u8,
) WriteError!void {
    try render(writer, promtail_template, .{
        .monitoring_private_ip = monitoring_private_ip,
        .instance_name = instance_name,
        .ip = ip,
        .region = region,
        .arch = arch,
    });
}

/// An instance Prometheus scrapes.
pub const ScrapeTarget = struct {
    name: []const u8,
    ip: []const u8,
    region: []const u8,
    arch: []const u8,
};

/// Prometheus configuration scraping every instance's binary and system metrics.
pub fn write_prometheus_config(
    writer: *Io.Writer,
    instances: []const ScrapeTarget,
) WriteError!void {
    try writer.writeAll(prometheus_head);
    for (instances) |instance| {
        try render(writer, prometheus_binary_job, instance);
        try render(writer, prometheus_system_job, instance);
    }
}

/// The Pyroscope agent script: records `perf` profiles of the binary and uploads them.
pub fn write_pyroscope_script(
    writer: *Io.Writer,
    monitoring_private_ip: []const u8,
    name: []const u8,
    ip: []const u8,
    region: []const u8,
    arch: []const u8,
) WriteError!void {
    try render(writer, pyroscope_script_template, .{
        .monitoring_private_ip = monitoring_private_ip,
        .name = name,
        .ip = ip,
        .region = region,
        .arch = arch,
    });
}

// --- Template text (commonware's, verbatim) -----------------------------------------------

/// YAML configuration for Grafana datasources (Prometheus, Loki, Tempo, and Pyroscope).
pub const datasources_yml =
    \\
    \\apiVersion: 1
    \\datasources:
    \\  - name: Prometheus
    \\    type: prometheus
    \\    url: http://localhost:9090
    \\    access: proxy
    \\    isDefault: true
    \\  - name: Loki
    \\    type: loki
    \\    url: http://localhost:3100
    \\    access: proxy
    \\    isDefault: false
    \\  - name: Tempo
    \\    type: tempo
    \\    url: http://localhost:3200
    \\    access: proxy
    \\    isDefault: false
    \\  - name: Pyroscope
    \\    type: grafana-pyroscope-datasource
    \\    url: http://localhost:4040
    \\    access: proxy
    \\    isDefault: false
    \\
;

/// YAML configuration for Grafana dashboard providers.
pub const all_yml =
    \\
    \\apiVersion: 1
    \\providers:
    \\  - name: 'default'
    \\    orgId: 1
    \\    folder: ''
    \\    type: file
    \\    options:
    \\      path: /var/lib/grafana/dashboards
    \\
;

/// YAML configuration for Loki.
pub const loki_config =
    \\
    \\auth_enabled: false
    \\target: all
    \\server:
    \\  http_listen_port: 3100
    \\  grpc_listen_port: 9095
    \\common:
    \\  ring:
    \\    kvstore:
    \\      store: inmemory
    \\  replication_factor: 1
    \\  instance_addr: 127.0.0.1
    \\schema_config:
    \\  configs:
    \\    - from: 2020-10-24
    \\      store: tsdb
    \\      object_store: filesystem
    \\      schema: v13
    \\      index:
    \\        prefix: index_
    \\        period: 24h
    \\storage_config:
    \\  tsdb_shipper:
    \\    active_index_directory: /loki/index
    \\    cache_location: /loki/index_cache
    \\  filesystem:
    \\    directory: /loki/chunks
    \\table_manager:
    \\  retention_deletes_enabled: true
    \\  retention_period: 12h
    \\compactor:
    \\  working_directory: /loki/compactor
    \\ingester:
    \\  wal:
    \\    dir: /loki/wal
    \\
;

/// YAML configuration for Pyroscope.
pub const pyroscope_config =
    \\
    \\target: all
    \\server:
    \\  http_listen_port: 4040
    \\  grpc_listen_port: 0
    \\pyroscopedb:
    \\  data_path: /var/lib/pyroscope
    \\self_profiling:
    \\  disable_push: true
    \\
;

/// YAML configuration for Tempo.
pub const tempo_config =
    \\
    \\server:
    \\  grpc_listen_port: 9096
    \\  grpc_server_max_recv_msg_size: 104857600
    \\  grpc_server_max_send_msg_size: 104857600
    \\  http_listen_port: 3200
    \\distributor:
    \\  receivers:
    \\    otlp:
    \\      protocols:
    \\        http:
    \\          endpoint: "0.0.0.0:4318"
    \\storage:
    \\  trace:
    \\    backend: local
    \\    local:
    \\      path: /var/tempo/traces
    \\    wal:
    \\      path: /var/tempo/wal
    \\ingester:
    \\  max_block_duration: 1h
    \\compactor:
    \\  compaction:
    \\    block_retention: 1h
    \\    compaction_cycle: 1h
    \\overrides:
    \\  defaults:
    \\    ingestion:
    \\      rate_limit_bytes: 1000000000
    \\      burst_size_bytes: 2000000000
    \\      max_traces_per_user: 500000
    \\    global:
    \\      max_bytes_per_trace: 100000000
    \\
;

/// Logrotate configuration for binary logs.
pub const logrotate_conf =
    \\
    \\/var/log/binary.log {
    \\    rotate 0
    \\    copytruncate
    \\    missingok
    \\    notifempty
    \\}
    \\
;

/// Systemd service file for the Pyroscope agent script.
pub const pyroscope_agent_service = expand(
    \\[Unit]
    \\Description=Pyroscope Agent (Perf Script Runner)
    \\Wants=network-online.target
    \\After=network-online.target binary.service
    \\
    \\[Service]
    \\Type=oneshot
    \\User=ubuntu
    \\ExecStart=<home>/pyroscope-agent.sh
    \\
    \\[Install]
    \\WantedBy=multi-user.target
    \\
);

/// Systemd timer file for the Pyroscope agent service.
pub const pyroscope_agent_timer =
    \\[Unit]
    \\Description=Run Pyroscope Agent periodically
    \\
    \\[Timer]
    \\# Wait a bit after boot before the first run
    \\OnBootSec=2min
    \\# Run roughly every minute after the last run finished
    \\OnUnitInactiveSec=1min
    \\Unit=pyroscope-agent.service
    \\# Randomize the delay to avoid thundering herd
    \\RandomizedDelaySec=10s
    \\
    \\[Install]
    \\WantedBy=timers.target
    \\
;

/// Template of an image service's systemd unit.
const service_file_template =
    \\[Unit]
    \\Description={description}
    \\Wants=network-online.target
    \\{after_line}
    \\Requires=docker.service
    \\
    \\[Service]
    \\ExecStartPre=-{docker_bin} rm -f {service}
    \\ExecStart={docker_bin} run --rm --name {service}{run_options} {image}{args}
    \\TimeoutStopSec=60
    \\Restart=always
    \\
    \\[Install]
    \\WantedBy=multi-user.target
    \\
;

/// Disables automatic APT upgrades and waits for active package operations.
pub const disable_automatic_apt_upgrades_cmd =
    \\set -e
    \\sudo timeout 10m cloud-init status --wait
    \\sudo systemctl mask --now apt-daily.timer apt-daily-upgrade.timer
    \\sudo tee /etc/apt/apt.conf.d/99-disable-periodic.conf >/dev/null <<'EOF'
    \\APT::Periodic::Enable "0";
    \\APT::Periodic::Update-Package-Lists "0";
    \\APT::Periodic::Unattended-Upgrade "0";
    \\EOF
    \\
    \\# Let active package operations finish instead of interrupting them.
    \\sudo timeout 10m sh -c '
    \\while
    \\    ! systemctl show --property=ActiveState --value apt-daily.service | grep -Eq "^(inactive|failed)$" ||
    \\    ! systemctl show --property=ActiveState --value apt-daily-upgrade.service | grep -Eq "^(inactive|failed)$" ||
    \\    fuser -s /var/lib/apt/daily_lock /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock /var/cache/apt/archives/lock; do
    \\    sleep 1
    \\done
    \\'
    \\
    \\for timer in apt-daily.timer apt-daily-upgrade.timer; do
    \\    [ "$(systemctl is-enabled "$timer" 2>/dev/null || true)" = masked ]
    \\done
    \\for setting in Enable Update-Package-Lists Unattended-Upgrade; do
    \\    [ "$(apt-config shell VALUE "APT::Periodic::$setting/i")" = "VALUE='0'" ]
    \\done
    \\
;

/// Template of phase 1 on the monitoring instance.
const monitoring_download_template = expand(
    \\
    \\# Clean up any previous download artifacts (allows retries to re-download fresh copies)
    \\rm -f <home>/prometheus.yml <home>/datasources.yml <home>/all.yml \
    \\      <home>/dashboard.json <home>/node-exporter-full.json <home>/loki.yml \
    \\      <home>/pyroscope.yml <home>/tempo.yml <home>/docker.tgz
    \\
    \\# Unmask services in case previous attempt left them masked
    \\sudo systemctl unmask docker prometheus loki pyroscope tempo node_exporter grafana tracer 2>/dev/null || true
    \\
    \\# Download all files from S3 concurrently via pre-signed URLs
    \\{WGET} -O <home>/docker.tgz '{docker_tgz}' &
    \\{WGET} -O <home>/prometheus.yml '{prometheus_config}' &
    \\{WGET} -O <home>/datasources.yml '{datasources_yml}' &
    \\{WGET} -O <home>/all.yml '{all_yml}' &
    \\{WGET} -O <home>/dashboard.json '{dashboard}' &
    \\{WGET} -O <home>/node-exporter-full.json '{node_exporter_dashboard}' &
    \\{WGET} -O <home>/loki.yml '{loki_yml}' &
    \\{WGET} -O <home>/pyroscope.yml '{pyroscope_yml}' &
    \\{WGET} -O <home>/tempo.yml '{tempo_yml}' &
    \\wait
    \\
    \\# Verify all downloads succeeded
    \\for f in prometheus.yml datasources.yml all.yml dashboard.json node-exporter-full.json \
    \\         loki.yml pyroscope.yml tempo.yml docker.tgz; do
    \\    if [ ! -f "<home>/$f" ]; then
    \\        echo "ERROR: Failed to download $f" >&2
    \\        exit 1
    \\    fi
    \\done
    \\
);

/// Installs Docker before the image services.
const image_services_head = expand(
    \\# Install Docker services
    \\rm -rf <home>/docker
    \\tar xzf <home>/docker.tgz -C <home>
    \\sudo install -m 0755 <home>/docker/* /usr/local/bin/
    \\sudo tee /etc/systemd/system/docker.service >/dev/null <<'EOF'
    \\[Unit]
    \\Description=Docker Application Container Engine
    \\After=network-online.target
    \\Wants=network-online.target
    \\
    \\[Service]
    \\Type=notify
    \\Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    \\ExecStart=/usr/local/bin/dockerd --host=unix:///var/run/docker.sock
    \\ExecReload=/bin/kill -s HUP $MAINPID
    \\TimeoutStartSec=120
    \\Restart=always
    \\RestartSec=2
    \\Delegate=yes
    \\KillMode=process
    \\LimitNOFILE=infinity
    \\LimitNPROC=infinity
    \\LimitCORE=infinity
    \\TasksMax=infinity
    \\OOMScoreAdjust=-500
    \\
    \\[Install]
    \\WantedBy=multi-user.target
    \\EOF
    \\sudo systemctl daemon-reload
    \\sudo systemctl enable --now docker
    \\
);

/// Template of phase 2 on the monitoring instance.
const monitoring_setup_template = expand(
    \\set -e
    \\
    \\# Enable BBR congestion control
    \\echo -e "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr" | sudo tee /etc/sysctl.d/99-bbr.conf >/dev/null && sudo sysctl -p /etc/sysctl.d/99-bbr.conf
    \\
    \\{image_services}
    \\
    \\# Create service directories
    \\sudo mkdir -p /opt/prometheus /opt/prometheus/data
    \\sudo mkdir -p /loki/index /loki/index_cache /loki/chunks /loki/compactor /loki/wal
    \\sudo mkdir -p /var/lib/pyroscope
    \\sudo mkdir -p /tempo/traces /tempo/wal
    \\sudo mkdir -p /etc/grafana/provisioning/datasources /etc/grafana/provisioning/dashboards /var/lib/grafana/dashboards
    \\
    \\# Install configuration files
    \\sudo mv <home>/prometheus.yml /opt/prometheus/prometheus.yml
    \\sudo mv <home>/datasources.yml /etc/grafana/provisioning/datasources/datasources.yml
    \\sudo mv <home>/all.yml /etc/grafana/provisioning/dashboards/all.yml
    \\sudo mv <home>/dashboard.json /var/lib/grafana/dashboards/dashboard.json
    \\sudo mv <home>/node-exporter-full.json /var/lib/grafana/dashboards/node-exporter-full.json
    \\sudo mkdir -p /etc/loki
    \\sudo mv <home>/loki.yml /etc/loki/loki.yml
    \\sudo chown root:root /etc/loki/loki.yml
    \\sudo mkdir -p /etc/pyroscope
    \\sudo mv <home>/pyroscope.yml /etc/pyroscope/pyroscope.yml
    \\sudo chown root:root /etc/pyroscope/pyroscope.yml
    \\sudo mkdir -p /etc/tempo
    \\sudo mv <home>/tempo.yml /etc/tempo/tempo.yml
    \\sudo chown root:root /etc/tempo/tempo.yml
    \\
);

/// Head of the monitoring services startup.
const start_monitoring_head =
    \\set -e
    \\
    \\# Start services
    \\sudo systemctl daemon-reload
    \\
;

/// Template of the optional apt phase on binary instances.
const apt_template =
    \\set -e
    \\sudo apt-get update -y
    \\sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {packages}
    \\
;

/// Template of phase 2 on binary instances.
const binary_download_template = expand(
    \\
    \\# Clean up any previous download artifacts (allows retries to re-download fresh copies)
    \\rm -f <home>/binary <home>/config.conf <home>/hosts.yaml \
    \\      <home>/promtail.yml <home>/binary.service \
    \\      <home>/pyroscope-agent.sh <home>/pyroscope-agent.service \
    \\      <home>/pyroscope-agent.timer <home>/docker.tgz \
    \\      <home>/logrotate.deb
    \\
    \\# Unmask services in case previous attempt left them masked
    \\sudo systemctl unmask docker promtail node_exporter binary 2>/dev/null || true
    \\
    \\# Download all files from S3 concurrently via pre-signed URLs
    \\{WGET} -O <home>/binary '{binary}' &
    \\{WGET} -O <home>/config.conf '{config}' &
    \\{WGET} -O <home>/hosts.yaml '{hosts}' &
    \\{WGET} -O <home>/promtail.yml '{promtail_config}' &
    \\{WGET} -O <home>/binary.service '{binary_service}' &
    \\{WGET} -O <home>/pyroscope-agent.sh '{pyroscope_script}' &
    \\{WGET} -O <home>/pyroscope-agent.service '{pyroscope_service}' &
    \\{WGET} -O <home>/pyroscope-agent.timer '{pyroscope_timer}' &
    \\{WGET} -O <home>/docker.tgz '{docker_tgz}' &
    \\{WGET} -O <home>/logrotate.deb '{logrotate_deb}' &
    \\wait
    \\
    \\# Verify all downloads succeeded
    \\for f in binary config.conf hosts.yaml promtail.yml binary.service \
    \\         pyroscope-agent.sh pyroscope-agent.service pyroscope-agent.timer \
    \\         docker.tgz logrotate.deb; do
    \\    if [ ! -f "<home>/$f" ]; then
    \\        echo "ERROR: Failed to download $f" >&2
    \\        exit 1
    \\    fi
    \\done
    \\
);

/// Template of the NVMe instance-store mount.
const nvme_setup_template =
    \\
    \\set -e
    \\cd /
    \\
    \\# Configure EC2 NVMe instance-store mounting
    \\NVME_MOUNT='{mount_directory}'
    \\sudo udevadm settle || true
    \\NVME_DEVICES="$(for model_path in /sys/block/nvme*n1/device/model; do
    \\    [ -e "$model_path" ] || continue
    \\    if grep -q 'Amazon EC2 NVMe Instance Storage' "$model_path"; then
    \\        basename "$(dirname "$(dirname "$model_path")")" | sed 's#^#/dev/#'
    \\    fi
    \\done | sort)"
    \\NVME_COUNT="$(printf '%s\n' "$NVME_DEVICES" | sed '/^$/d' | wc -l)"
    \\
    \\if [ "$NVME_COUNT" -eq 0 ]; then
    \\    echo "ERROR: NVMe instance storage requested but no EC2 NVMe instance-store devices were found" >&2
    \\    exit 1
    \\fi
    \\
    \\sudo mkdir -p "$NVME_MOUNT"
    \\
    \\if [ "$NVME_COUNT" -eq 1 ]; then
    \\    NVME_TARGET="$(printf '%s\n' "$NVME_DEVICES" | head -n1)"
    \\else
    \\    NVME_TARGET=/dev/md/commonware-nvme
    \\    sudo mkdir -p /dev/md
    \\    sudo mdadm --assemble "$NVME_TARGET" $NVME_DEVICES >/dev/null 2>&1 || true
    \\    if [ ! -e "$NVME_TARGET" ]; then
    \\        sudo mdadm --create "$NVME_TARGET" --name=commonware-nvme --level=0 --raid-devices="$NVME_COUNT" --force $NVME_DEVICES
    \\    fi
    \\    sudo udevadm settle || true
    \\fi
    \\
    \\if ! sudo blkid "$NVME_TARGET" >/dev/null 2>&1; then
    \\    sudo mkfs.ext4 -F "$NVME_TARGET"
    \\fi
    \\if ! findmnt -rn --mountpoint "$NVME_MOUNT" >/dev/null; then
    \\    NVME_STAGE="$(mktemp -d /tmp/commonware-nvme.XXXXXX)"
    \\    cleanup_stage() {{
    \\        if [ -n "${{NVME_STAGE:-}}" ]; then
    \\            sudo umount "$NVME_STAGE" >/dev/null 2>&1 || true
    \\            sudo rmdir "$NVME_STAGE" >/dev/null 2>&1 || true
    \\        fi
    \\    }}
    \\    trap cleanup_stage EXIT
    \\    sudo mount "$NVME_TARGET" "$NVME_STAGE"
    \\    sudo tar -C "$NVME_MOUNT" -cpf - . | sudo tar -C "$NVME_STAGE" -xpf -
    \\    sudo umount "$NVME_STAGE"
    \\    sudo rmdir "$NVME_STAGE"
    \\    NVME_STAGE=
    \\    sudo mount "$NVME_TARGET" "$NVME_MOUNT"
    \\fi
    \\
    \\NVME_MOUNT_SOURCE="$(findmnt -rn --mountpoint "$NVME_MOUNT" -o SOURCE || true)"
    \\if [ -z "$NVME_MOUNT_SOURCE" ]; then
    \\    echo "ERROR: NVMe instance storage was not mounted at $NVME_MOUNT" >&2
    \\    exit 1
    \\fi
    \\if [ "$(readlink -f "$NVME_MOUNT_SOURCE")" != "$(readlink -f "$NVME_TARGET")" ]; then
    \\    echo "ERROR: $NVME_MOUNT is mounted from $NVME_MOUNT_SOURCE, expected $NVME_TARGET" >&2
    \\    exit 1
    \\fi
    \\
    \\sudo chown -R ubuntu:ubuntu "$NVME_MOUNT"
    \\
;

/// Pyroscope agent setup when profiling.
const perf_setup = expand(
    \\
    \\# Setup pyroscope agent (perf symlink must be created after linux-tools installed via apt)
    \\sudo ln -sf "$(find /usr/lib/linux-tools/*/perf | head -1)" /usr/local/bin/perf
    \\sudo chmod +x <home>/pyroscope-agent.sh
    \\sudo mv <home>/pyroscope-agent.service /etc/systemd/system/pyroscope-agent.service
    \\sudo mv <home>/pyroscope-agent.timer /etc/systemd/system/pyroscope-agent.timer
    \\
);

/// Template of phase 3 on binary instances.
const binary_setup_template = expand(
    \\set -e
    \\
    \\# Enable BBR congestion control and tune TCP buffers for cross-region flows
    \\echo -e "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\nnet.core.rmem_max=16777216\nnet.core.wmem_max=16777216\nnet.ipv4.tcp_rmem=4096 2097152 16777216\nnet.ipv4.tcp_wmem=4096 262144 16777216\nnet.ipv4.tcp_slow_start_after_idle=0" | sudo tee /etc/sysctl.d/99-bbr.conf >/dev/null && sudo sysctl -p /etc/sysctl.d/99-bbr.conf
    \\
    \\# The default_qdisc sysctl only applies to interfaces attached after it is
    \\# set, so install fq (which enforces BBR's pacing) on every tx queue of the
    \\# primary interface explicitly and persist the setup across reboots.
    \\sudo tee /usr/local/bin/setup-qdisc.sh >/dev/null <<'EOF'
    \\#!/bin/bash
    \\set -e
    \\IFACE=$(ip -o route get 8.8.8.8 | awk '{{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}}')
    \\# Single-queue interfaces reject mq, so pace on the root instead.
    \\if tc qdisc replace dev "$IFACE" root handle 1: mq; then
    \\  NQ=$(ls -d "/sys/class/net/$IFACE/queues/tx-"* | wc -l)
    \\  for h in $(seq 1 "$NQ"); do
    \\    tc qdisc del dev "$IFACE" parent "1:$(printf '%x' "$h")" 2>/dev/null || true
    \\    tc qdisc add dev "$IFACE" parent "1:$(printf '%x' "$h")" fq
    \\  done
    \\else
    \\  tc qdisc replace dev "$IFACE" root fq
    \\fi
    \\EOF
    \\sudo chmod +x /usr/local/bin/setup-qdisc.sh
    \\sudo tee /etc/systemd/system/setup-qdisc.service >/dev/null <<'EOF'
    \\[Unit]
    \\Description=Install fq pacing qdisc on the primary interface
    \\After=network-online.target
    \\Wants=network-online.target
    \\
    \\[Service]
    \\Type=oneshot
    \\ExecStart=/usr/local/bin/setup-qdisc.sh
    \\
    \\[Install]
    \\WantedBy=multi-user.target
    \\EOF
    \\sudo systemctl daemon-reload
    \\sudo systemctl enable --now setup-qdisc.service
    \\
    \\{image_services}
    \\
    \\# Install deb packages
    \\sudo dpkg -i <home>/logrotate.deb
    \\
    \\# Setup Promtail
    \\sudo mkdir -p /etc/promtail /var/lib/promtail
    \\sudo mv <home>/promtail.yml /etc/promtail/promtail.yml
    \\sudo chown root:root /etc/promtail/promtail.yml
    \\
    \\# Setup binary
    \\chmod +x <home>/binary
    \\sudo touch /var/log/binary.log && sudo chown ubuntu:ubuntu /var/log/binary.log
    \\sudo mv <home>/binary.service /etc/systemd/system/binary.service
    \\
    \\# Setup logrotate
    \\sudo tee /etc/logrotate.d/binary >/dev/null <<'EOF'
    \\{LOGROTATE_CONF}EOF
    \\echo "0 * * * * /usr/sbin/logrotate /etc/logrotate.d/binary" | crontab -
    \\
    \\{perf_setup}
    \\# Start services
    \\sudo systemctl daemon-reload
    \\sudo systemctl enable node_exporter
    \\sudo systemctl enable promtail
    \\sudo systemctl enable binary
    \\sudo systemctl start node_exporter
    \\sudo systemctl start promtail
    \\
    \\# Don't abort the setup script if the caller-provided binary fails to start; the deployer
    \\# polls the service afterwards and warns on an unhealthy binary (see poll_service_active)
    \\# so create can still complete and the binary can be fixed with a later update.
    \\sudo systemctl start binary || true{pyroscope_enable}
);

/// Template of the Promtail configuration.
const promtail_template =
    \\
    \\server:
    \\  http_listen_port: 9080
    \\  grpc_listen_port: 0
    \\positions:
    \\  filename: /var/lib/promtail/positions.yaml
    \\clients:
    \\  - url: http://{monitoring_private_ip}:3100/loki/api/v1/push
    \\scrape_configs:
    \\  - job_name: binary_logs
    \\    static_configs:
    \\      - targets:
    \\          - localhost
    \\        labels:
    \\          deployer_name: '{instance_name}'
    \\          deployer_ip: '{ip}'
    \\          deployer_region: '{region}'
    \\          deployer_arch: '{arch}'
    \\          __path__: /var/log/binary.log
    \\
;

/// Head of the Prometheus configuration.
const prometheus_head =
    \\
    \\global:
    \\  scrape_interval: 15s
    \\scrape_configs:
    \\  - job_name: 'monitoring_system'
    \\    static_configs:
    \\      - targets: ['localhost:9100']
    \\
;

/// Template of an instance's binary scrape job.
const prometheus_binary_job =
    \\
    \\  - job_name: '{name}_binary'
    \\    static_configs:
    \\      - targets: ['{ip}:9090']
    \\        labels:
    \\          deployer_name: '{name}'
    \\          deployer_ip: '{ip}'
    \\          deployer_region: '{region}'
    \\          deployer_arch: '{arch}'
    \\
;

/// Template of an instance's system scrape job.
const prometheus_system_job =
    \\
    \\  - job_name: '{name}_system'
    \\    static_configs:
    \\      - targets: ['{ip}:9100']
    \\        labels:
    \\          deployer_name: '{name}'
    \\          deployer_ip: '{ip}'
    \\          deployer_region: '{region}'
    \\          deployer_arch: '{arch}'
    \\
;

/// Systemd service file for the deployed binary.
pub const binary_service_unit = expand(
    \\[Unit]
    \\Description=Deployed Binary Service
    \\After=network.target
    \\
    \\[Service]
    \\ExecStart=<home>/binary --hosts=<home>/hosts.yaml --config=<home>/config.conf
    \\TimeoutStopSec=60
    \\Restart=always
    \\User=ubuntu
    \\LimitNOFILE=infinity
    \\StandardOutput=append:/var/log/binary.log
    \\StandardError=append:/var/log/binary.log
    \\
    \\[Install]
    \\WantedBy=multi-user.target
    \\
);

/// Template of the Pyroscope agent script.
const pyroscope_script_template =
    \\#!/bin/bash
    \\set -e
    \\
    \\SERVICE_NAME="binary.service"
    \\PERF_DATA_FILE="/tmp/perf.data"
    \\PERF_STACK_FILE="/tmp/perf.stack"
    \\PROFILE_DURATION=60 # seconds
    \\PERF_FREQ=100 # Hz
    \\
    \\# Construct the Pyroscope application name with tags (URL-encoded)
    \\RAW_APP_NAME="binary{{deployer_name={name},deployer_ip={ip},deployer_region={region},deployer_arch={arch}}}"
    \\APP_NAME=$(printf '%s' "$RAW_APP_NAME" | python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.stdin.read()))")
    \\
    \\# Get the PID of the binary service
    \\PID=$(systemctl show --property MainPID ${{SERVICE_NAME}} | cut -d= -f2)
    \\if [ -z "$PID" ] || [ "$PID" -eq 0 ]; then
    \\  echo "Error: Could not get PID for ${{SERVICE_NAME}}." >&2
    \\  exit 1
    \\fi
    \\
    \\# Record performance data
    \\echo "Recording perf data for PID ${{PID}}..."
    \\sudo perf record -F ${{PERF_FREQ}} -p ${{PID}} -o ${{PERF_DATA_FILE}} -g --call-graph fp -- sleep ${{PROFILE_DURATION}}
    \\
    \\# Generate folded stack report
    \\echo "Generating folded stack report..."
    \\sudo perf report -i ${{PERF_DATA_FILE}} --stdio --no-children -g folded,0,caller,count -s comm | \
    \\    awk '/^[0-9]+\.[0-9]+%/ {{ comm = $2 }} /^[0-9]/ {{ print comm ";" substr($0, index($0, $2)), $1 }}' > ${{PERF_STACK_FILE}}
    \\
    \\# Check if stack file is empty (perf might fail silently sometimes)
    \\if [ ! -s "${{PERF_STACK_FILE}}" ]; then
    \\    echo "Warning: ${{PERF_STACK_FILE}} is empty. Skipping upload." >&2
    \\    # Clean up empty perf.data
    \\    sudo rm -f ${{PERF_DATA_FILE}} ${{PERF_STACK_FILE}}
    \\    exit 0
    \\fi
    \\
    \\# Calculate timestamps
    \\UNTIL_TS=$(date +%s)
    \\FROM_TS=$((UNTIL_TS - PROFILE_DURATION))
    \\
    \\# Upload to Pyroscope
    \\echo "Uploading profile to Pyroscope at {monitoring_private_ip}..."
    \\wget --post-file="${{PERF_STACK_FILE}}" \
    \\    --header="Content-Type: text/plain" \
    \\    --quiet \
    \\    -O /dev/null \
    \\    "http://{monitoring_private_ip}:4040/ingest?name=${{APP_NAME}}&format=folded&units=samples&aggregationType=sum&sampleType=cpu&from=${{FROM_TS}}&until=${{UNTIL_TS}}&spyName=perf"
    \\
    \\echo "Profile upload complete."
    \\sudo rm -f ${{PERF_DATA_FILE}} ${{PERF_STACK_FILE}}
    \\
;

test {
    _ = @import("services_test.zig");
}
