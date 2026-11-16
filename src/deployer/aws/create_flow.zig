//! The `create` command (commonware `create.rs`'s `create`): validates the configuration,
//! caches tools, images, and files in S3, builds each region's network, launches the
//! instances, uploads their configuration, installs them over SSH, and marks the deployment
//! created. The checks and plans it relies on live in `create.zig`.
//!
//! Regions are built concurrently, launches run through `create.run_launches`, and instances
//! are configured `concurrency` at a time alongside monitoring, as in commonware. S3 uploads
//! and instance waits run one at a time (commonware overlaps them; the result is the same).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Io = std.Io;
const aws = @import("mod.zig");
const create = @import("create.zig");
const ec2_module = @import("ec2.zig");
const ec2_api = @import("ec2_api.zig");
const images = @import("images.zig");
const s3 = @import("s3.zig");
const services = @import("services.zig");
const deployments_module = @import("deployments.zig");
const Client = @import("client.zig").Client;
const Session = @import("session.zig").Session;
const IpAddr = @import("../ip.zig").IpAddr;
const Architecture = aws.Architecture;
const DeploymentFile = services.DeploymentFile;

const log = std.log.scoped(.deployer);

/// Most instance IDs per DescribeInstances call (commonware `MAX_DESCRIBE_BATCH`).
pub const describe_batch_max = 1000;

/// An instance type's architecture and whether it has NVMe instance storage.
const TypeInfo = struct { instance_type: []const u8, architecture: Architecture, nvme: bool };

/// Presigned URLs of the tools for one architecture (commonware `ToolUrls`).
const ToolUrls = struct { docker: []const u8, logrotate: []const u8 };

const ImageEntry = struct { architecture: Architecture, image: []const u8, url: []const u8 };

/// What `create` builds in one region (commonware `RegionResources`).
const Region = struct {
    name: []const u8,
    /// Position among the sorted regions: the VPC is `10.{index}.0.0/16`.
    index: usize,
    instance_types: []const []const u8,
    has_binaries: bool,
    vpc_id: []const u8 = "",
    vpc_cidr: []const u8 = "",
    route_table_id: []const u8 = "",
    subnets: []const create.Subnet = &.{},
    az_support: []const create.AzSupport = &.{},
    binary_sg_id: []const u8 = "",
    monitoring_sg_id: ?[]const u8 = null,

    fn resources(region: *const Region) create.RegionResources {
        return .{
            .region = region.name,
            .subnets = region.subnets,
            .az_support = region.az_support,
        };
    }
};

/// A launched binary instance (commonware `Deployment`).
pub const Deployment = struct {
    instance: *const aws.InstanceConfig,
    id: []const u8 = "",
    ip: []const u8 = "",
};

/// A per-deployment file uploaded once per digest.
const Upload = struct { kind: DeploymentFile, digest: [64]u8, url: []const u8 };

const State = struct {
    session: *Session,
    config: aws.Config,
    directory: []const u8 = "",
    region_names: []const []const u8 = &.{},
    regions: []Region = &.{},
    deployer_ip: []const u8 = "",
    key_name: []const u8 = "",
    private_key: []const u8 = "",
    public_key: []const u8 = "",
    types: std.ArrayList(TypeInfo) = .empty,
    monitoring_architecture: Architecture = undefined,
    architectures: std.EnumSet(Architecture) = .empty,
    bucket: []const u8 = "",
    s3: *const Client = undefined,
    node_exporter_dashboard_url: []const u8 = "",
    tools: std.EnumArray(Architecture, ToolUrls) = .initUndefined(),
    image_urls: std.ArrayList(ImageEntry) = .empty,
    files: []const s3.InstanceUrls = &.{},
    groups: []const create.GroupSelection = &.{},
    monitoring_id: []const u8 = "",
    monitoring_ip: []const u8 = "",
    monitoring_private_ip: []const u8 = "",
    deployments: []Deployment = &.{},
    monitoring_urls: services.MonitoringUrls = undefined,
    instance_urls: []services.InstanceUrls = &.{},

    fn arena(state: *const State) Allocator {
        return state.session.arena;
    }

    fn type_info(state: *State, instance_type: []const u8) *TypeInfo {
        for (state.types.items) |*info| {
            if (std.mem.eql(u8, info.instance_type, instance_type)) return info;
        }
        unreachable; // Proof: `detect_types` records every configured instance type.
    }

    fn region(state: *State, name: []const u8) *Region {
        for (state.regions) |*entry| if (std.mem.eql(u8, entry.name, name)) return entry;
        // Proof: `plan_regions` makes the monitoring region and every instance's.
        unreachable;
    }

    fn image_list(
        state: *State,
        names: []const []const u8,
        architecture: Architecture,
    ) ![]const services.ImageUrl {
        const out = try state.arena().alloc(services.ImageUrl, names.len);
        for (names, out) |name, *slot| {
            const url = for (state.image_urls.items) |entry| {
                const same = entry.architecture == architecture;
                if (same and std.mem.eql(u8, entry.image, name)) break entry.url;
            } else unreachable; // Proof: `cache_images` caches each image the instances run.
            slot.* = .{ .image = name, .url = url };
        }
        return out;
    }
};

/// Deploys the configuration at `config_path`, configuring at most `concurrency` binary
/// instances at once (commonware `create`).
pub fn create_deployment(session: *Session, config_path: []const u8, concurrency: u64) !void {
    assert(concurrency >= 1);
    var state: State = .{ .session = session, .config = try session.load_config(config_path) };
    log.info("loaded configuration: tag={s}", .{state.config.tag});
    // Validate before allocating any AWS resources.
    if (create.validate_names(&state.config)) |failure| return session.fail(failure);
    if (create.validate_storage_config(&state.config)) |failure| return session.fail(failure);
    try plan_regions(&state);
    try prepare_directory(&state);
    try detect_types(&state);
    try cache_tools(&state);
    try cache_images(&state);
    log.info("uploading unique binaries and configs to S3", .{});
    const tag = state.config.tag;
    const instances = state.config.instances;
    const bucket = state.bucket;
    const files = try s3.upload_instance_files(state.s3, session.arena, bucket, tag, instances);
    state.files = switch (files) {
        .ok => |uploaded| uploaded,
        .failure => |failure| return session.fail(failure),
    };
    log.info("uploaded all instance binaries and configs", .{});
    try init_regions(&state);
    try launch(&state);
    try wait_running(&state);
    try upload_configs(&state);
    try configure(&state, concurrency);
    try link_monitoring(&state);
    const parts = [_][]const u8{ state.directory, aws.created_file_name };
    const created = try std.fs.path.join(session.arena, &parts);
    try session.write_file(created, "");
    log.info("deployment complete: monitoring={s} binaries={d}", .{
        state.monitoring_ip, state.deployments.len,
    });
}

/// The regions, checked to be enabled before anything is written.
fn plan_regions(state: *State) !void {
    const session = state.session;
    const arena = state.arena();
    state.region_names = try session.regions_of(&state.config);
    var monitoring = try session.ec2(aws.monitoring_region);
    const enabled = ec2_api.get_enabled_regions(&monitoring) catch |err| {
        return session.ec2_failed(&monitoring, err);
    };
    var disabled: std.ArrayList([]const u8) = .empty;
    for (state.region_names) |name| {
        if (!contains(enabled, name)) try disabled.append(arena, name);
    }
    if (disabled.items.len > 0) return session.fail(.{ .regions_not_enabled = disabled.items });
    log.info("validated all regions are enabled: regions={d}", .{state.region_names.len});
    state.regions = try arena.alloc(Region, state.region_names.len);
    for (state.region_names, state.regions, 0..) |name, *entry, index| {
        var types: std.ArrayList([]const u8) = .empty;
        if (std.mem.eql(u8, name, aws.monitoring_region)) {
            try append_distinct(arena, &types, state.config.monitoring.instance_type);
        }
        var has_binaries = false;
        for (state.config.instances) |instance| {
            if (!std.mem.eql(u8, instance.region, name)) continue;
            has_binaries = true;
            try append_distinct(arena, &types, instance.instance_type);
        }
        assert(types.items.len > 0);
        entry.* = .{
            .name = name,
            .index = index,
            .instance_types = types.items,
            .has_binaries = has_binaries,
        };
    }
}

/// Creates the deployment directory, generates the SSH key, and persists the metadata early
/// so `destroy --tag` works after a failure.
fn prepare_directory(state: *State) !void {
    const session = state.session;
    const arena = state.arena();
    const tag = state.config.tag;
    state.directory = try session.tag_directory(tag);
    if (session.exists(state.directory)) return session.fail(.creation_attempted);
    Io.Dir.cwd().createDirPath(session.io, state.directory) catch |err| {
        return session.fail(.{ .io = .{ .path = state.directory, .err = err } });
    };
    log.info("created tag directory: path={s}", .{state.directory});
    state.deployer_ip = try session.public_ip();
    log.info("recovered public IP: ip={s}", .{state.deployer_ip});

    state.key_name = try std.fmt.allocPrint(arena, "deployer-{s}", .{tag});
    const key_file = try std.fmt.allocPrint(arena, "id_rsa_{s}", .{tag});
    state.private_key = try std.fs.path.join(arena, &.{ state.directory, key_file });
    const keygen: []const []const u8 = &.{
        "ssh-keygen", "-t", "rsa", "-b", "4096", "-f", state.private_key, "-N", "",
    };
    const output = session.local.run(arena, keygen) catch |err| switch (err) {
        error.OutOfMemory, error.Canceled => |e| return e,
        else => return session.fail(.{ .io = .{ .path = "ssh-keygen", .err = err } }),
    };
    if (output != null) return session.fail(.keygen_failed);
    const public_path = try std.fmt.allocPrint(arena, "{s}.pub", .{state.private_key});
    state.public_key = try session.read_file(public_path);

    const now_s: u64 = @intCast(@max(0, Io.Clock.real.now(session.io).toSeconds()));
    const metadata: aws.Metadata = .{
        .tag = tag,
        .created_at = now_s,
        .regions = state.region_names,
        .instance_count = state.config.instances.len,
    };
    var text: Io.Writer.Allocating = .init(arena);
    try metadata.write(&text.writer);
    const path = try std.fs.path.join(arena, &.{ state.directory, aws.metadata_file_name });
    try session.write_file(path, text.written());
    log.info("persisted deployment metadata", .{});
}

/// Detects each instance type's architecture and each binary type's NVMe instance storage.
fn detect_types(state: *State) !void {
    const session = state.session;
    const arena = state.arena();
    var monitoring = try session.ec2(aws.monitoring_region);
    var names: std.ArrayList([]const u8) = .empty;
    try append_distinct(arena, &names, state.config.monitoring.instance_type);
    var binary: std.ArrayList([]const u8) = .empty;
    for (state.config.instances) |instance| {
        try append_distinct(arena, &names, instance.instance_type);
        try append_distinct(arena, &binary, instance.instance_type);
    }
    log.info("detecting architectures for instance types", .{});
    for (names.items) |name| {
        const architecture = ec2_api.detect_architecture(&monitoring, name) catch |err| {
            return session.ec2_failed(&monitoring, err);
        };
        log.info("detected architecture: architecture={f} instance_type={s}", .{
            architecture, name,
        });
        const info: TypeInfo = .{
            .instance_type = name,
            .architecture = architecture,
            .nvme = false,
        };
        try state.types.append(arena, info);
    }
    // commonware walks the binary types as a `BTreeSet`.
    std.sort.pdq([]const u8, binary.items, {}, less_than);
    for (binary.items) |name| {
        const supported = ec2_api.supports_nvme_instance_storage(&monitoring, name) catch |err| {
            return session.ec2_failed(&monitoring, err);
        };
        log.info("detected NVMe instance-store support: instance_type={s} supported={}", .{
            name, supported,
        });
        state.type_info(name).nvme = supported;
    }
    const monitoring_type = state.config.monitoring.instance_type;
    state.monitoring_architecture = state.type_info(monitoring_type).architecture;
    state.architectures.insert(state.monitoring_architecture);
    for (state.config.instances) |instance| {
        state.architectures.insert(state.type_info(instance.instance_type).architecture);
    }
    assert(state.architectures.count() >= 1);
}

/// Sets up the bucket and caches the dashboard and each architecture's tools.
fn cache_tools(state: *State) !void {
    const session = state.session;
    const arena = state.arena();
    state.bucket = try s3.get_bucket_name(session.io, arena, session.home);
    log.info("setting up S3 bucket: bucket={s}", .{state.bucket});
    state.s3 = try session.s3();
    if (try s3.ensure_bucket_exists(state.s3, arena, state.bucket)) |failure| {
        return session.fail(failure);
    }
    log.info("uploading tools to S3", .{});
    const dashboard = services.grafana_node_exporter_dashboard_version;
    state.node_exporter_dashboard_url = try cache_tool(
        state,
        try written(arena, services.write_grafana_node_exporter_dashboard_s3_key, .{dashboard}),
        try written(
            arena,
            services.write_grafana_node_exporter_dashboard_download_url,
            .{dashboard},
        ),
    );
    var iterator = state.architectures.iterator();
    while (iterator.next()) |architecture| {
        const docker = services.docker_version;
        const logrotate = services.logrotate_version;
        const arch = architecture;
        state.tools.set(architecture, .{
            .docker = try cache_tool(
                state,
                try written(arena, services.write_docker_bin_s3_key, .{ docker, architecture }),
                try written(arena, services.write_docker_download_url, .{ docker, architecture }),
            ),
            .logrotate = try cache_tool(
                state,
                try written(arena, services.write_logrotate_bin_s3_key, .{ logrotate, arch }),
                try written(arena, services.write_logrotate_download_url, .{ logrotate, arch }),
            ),
        });
    }
    log.info("tools uploaded", .{});
}

/// Presigns the tool at `key`, downloading it from `url` and uploading it first when the
/// bucket lacks it. The download is held in scratch memory (commonware stages it on disk).
fn cache_tool(state: *State, key: []const u8, url: []const u8) ![]const u8 {
    const session = state.session;
    switch (try s3.object_exists(state.s3, session.arena, state.bucket, key)) {
        .failure => |failure| return session.fail(failure),
        .ok => |exists| if (exists) {
            log.info("tool already in S3: key={s}", .{key});
            const expires_s = s3.presign_duration_s;
            return s3.presign_url(state.s3, session.arena, state.bucket, key, expires_s);
        },
    }
    log.info("tool not in S3, downloading and uploading: key={s}", .{key});
    var scratch: std.heap.ArenaAllocator = .init(session.gpa);
    defer scratch.deinit();
    const body = try session.download(scratch.allocator(), url);
    return upload(state, key, .{ .static = body });
}

/// Caches each image the instances run, once per architecture.
fn cache_images(state: *State) !void {
    log.info("caching container images in S3", .{});
    for (services.monitoring_images) |image| {
        try cache_image(state, image, state.monitoring_architecture);
    }
    for (state.config.instances) |instance| {
        const architecture = state.type_info(instance.instance_type).architecture;
        for (services.binary_images) |image| try cache_image(state, image, architecture);
    }
    log.info("container images cached in S3", .{});
}

fn cache_image(state: *State, image: []const u8, architecture: Architecture) !void {
    for (state.image_urls.items) |entry| {
        if (entry.architecture == architecture and std.mem.eql(u8, entry.image, image)) return;
    }
    const url = try images.cache_image(
        state.session,
        state.s3,
        state.bucket,
        state.directory,
        image,
        architecture,
    );
    try state.image_urls.append(state.arena(), .{
        .architecture = architecture,
        .image = image,
        .url = url,
    });
}

/// Uploads `source` to `key` unless it is there, then presigns it.
fn upload(state: *State, key: []const u8, source: s3.UploadSource) ![]const u8 {
    const session = state.session;
    const expires_s = s3.presign_duration_s;
    const bucket = state.bucket;
    const arena = session.arena;
    const cached = try s3.cache_and_presign(state.s3, arena, bucket, key, source, expires_s);
    return switch (cached) {
        .ok => |url| url,
        .failure => |failure| session.fail(failure),
    };
}

// --- Regions -----------------------------------------------------------------------------------

const RegionJob = fn (*State, *Region, *ec2_api.Ec2) anyerror!void;

/// Runs `job` for every region concurrently and returns the first error once all finish.
fn each_region(state: *State, comptime job: RegionJob) !void {
    const io = state.session.io;
    const slots = try state.arena().alloc(?anyerror, state.regions.len);
    @memset(slots, null);
    var group: Io.Group = .init;
    defer group.cancel(io);
    for (state.regions, slots) |*entry, *slot| {
        group.async(io, region_task(job), .{ state, entry, slot });
    }
    try group.await(io);
    for (slots) |slot| if (slot) |err| return err;
}

fn region_task(comptime job: RegionJob) fn (*State, *Region, *?anyerror) void {
    return struct {
        fn run(state: *State, entry: *Region, slot: *?anyerror) void {
            var regional = state.session.ec2(entry.name) catch |err| {
                slot.* = err;
                return;
            };
            job(state, entry, &regional) catch |err| {
                slot.* = state.session.ec2_failed(&regional, err);
            };
        }
    }.run;
}

/// Builds every region's network, selects the grouped instances' availability zones, creates
/// the binary security groups, and peers each binary region with monitoring.
fn init_regions(state: *State) !void {
    const session = state.session;
    log.info("initializing resources: regions={d}", .{state.regions.len});
    try each_region(state, init_region);
    log.info("initialized resources: regions={d}", .{state.regions.len});
    const resources = try state.arena().alloc(create.RegionResources, state.regions.len);
    for (resources, state.regions) |*out, *entry| out.* = entry.resources();
    var failure: ?@import("failure.zig").Failure = null;
    const instances = state.config.instances;
    state.groups = create.select_availability_zone_groups(
        state.arena(),
        instances,
        resources,
        &failure,
    ) catch |err| switch (err) {
        error.Invalid => return session.fail(failure.?),
        error.OutOfMemory => return error.OutOfMemory,
    };
    log.info("creating binary security groups", .{});
    try each_region(state, create_binary_group);
    log.info("created binary security groups", .{});
    log.info("initializing VPC peering connections", .{});
    try each_region(state, peer_region);
    log.info("initialized VPC peering connections", .{});
}

/// One region's VPC, gateway, route table, a subnet per availability zone, the monitoring
/// security group (monitoring region only), and the key pair.
fn init_region(state: *State, entry: *Region, regional: *ec2_api.Ec2) anyerror!void {
    const arena = state.arena();
    const tag = state.config.tag;
    const name = entry.name;
    log.info("created EC2 client: region={s}", .{name});
    entry.az_support = try ec2_api.find_az_instance_support(regional, entry.instance_types);
    log.info("found availability zones: region={s} count={d}", .{ name, entry.az_support.len });
    entry.vpc_cidr = try std.fmt.allocPrint(arena, "10.{d}.0.0/16", .{entry.index});
    entry.vpc_id = try ec2_api.create_vpc(regional, entry.vpc_cidr, tag);
    log.info("created VPC: vpc={s} region={s}", .{ entry.vpc_id, name });
    const igw_id = try ec2_api.create_and_attach_igw(regional, entry.vpc_id, tag);
    log.info("created and attached IGW: igw={s} region={s}", .{ igw_id, name });
    entry.route_table_id = try ec2_api.create_route_table(regional, entry.vpc_id, igw_id, tag);
    log.info("created route table: route_table={s} region={s}", .{ entry.route_table_id, name });
    const subnets = try arena.alloc(create.Subnet, entry.az_support.len);
    for (entry.az_support, subnets, 0..) |support, *subnet, az_index| {
        const cidr = try std.fmt.allocPrint(arena, "10.{d}.{d}.0/24", .{ entry.index, az_index });
        const id = try ec2_api.create_subnet(
            regional,
            entry.vpc_id,
            entry.route_table_id,
            cidr,
            support.az,
            tag,
        );
        log.info("created subnet: subnet={s} az={s} region={s}", .{ id, support.az, name });
        subnet.* = .{ .az = support.az, .id = id };
    }
    entry.subnets = subnets;
    if (std.mem.eql(u8, name, aws.monitoring_region)) {
        const ip = state.deployer_ip;
        entry.monitoring_sg_id =
            try ec2_api.create_security_group_monitoring(regional, entry.vpc_id, ip, tag);
        log.info("created monitoring security group: sg={s}", .{entry.monitoring_sg_id.?});
    }
    try ec2_api.import_key_pair(regional, state.key_name, state.public_key);
    log.info("imported key pair: key={s} region={s}", .{ state.key_name, name });
    assert(entry.subnets.len == entry.az_support.len);
}

/// The binary security group; monitoring's rules are added once it runs.
fn create_binary_group(state: *State, entry: *Region, regional: *ec2_api.Ec2) anyerror!void {
    const ip = state.deployer_ip;
    const tag = state.config.tag;
    const ports = state.config.ports;
    entry.binary_sg_id =
        try ec2_api.create_security_group_binary(regional, entry.vpc_id, ip, tag, ports);
    log.info("created binary security group: sg={s} region={s}", .{
        entry.binary_sg_id, entry.name,
    });
}

/// Peers a binary region's VPC with monitoring's and routes between them.
fn peer_region(state: *State, entry: *Region, regional: *ec2_api.Ec2) anyerror!void {
    if (std.mem.eql(u8, entry.name, aws.monitoring_region) or !entry.has_binaries) return;
    const session = state.session;
    const tag = state.config.tag;
    const monitoring = state.region(aws.monitoring_region);
    var requester = try session.ec2(aws.monitoring_region);
    const peer_id = ec2_api.create_vpc_peering_connection(
        &requester,
        monitoring.vpc_id,
        entry.vpc_id,
        entry.name,
        tag,
    ) catch |err| return session.ec2_failed(&requester, err);
    log.info("created VPC peering connection: peer={s} region={s}", .{ peer_id, entry.name });
    try ec2_api.wait_for_vpc_peering_connection(regional, peer_id);
    log.info("VPC peering connection is available: peer={s}", .{peer_id});
    try ec2_api.accept_vpc_peering_connection(regional, peer_id);
    log.info("accepted VPC peering connection: peer={s}", .{peer_id});
    const route_table = monitoring.route_table_id;
    ec2_api.add_route(&requester, route_table, entry.vpc_cidr, peer_id) catch |err| {
        return session.ec2_failed(&requester, err);
    };
    try ec2_api.add_route(regional, entry.route_table_id, monitoring.vpc_cidr, peer_id);
    log.info("added routes for VPC peering connection: peer={s}", .{peer_id});
}

// --- Launch ------------------------------------------------------------------------------------

const Ami = struct { region: []const u8, architecture: Architecture, id: []const u8 };

/// Looks up the AMIs, then launches monitoring and every binary instance.
fn launch(state: *State) !void {
    const arena = state.arena();
    log.info("launching instances", .{});
    var amis: std.ArrayList(Ami) = .empty;
    _ = try find_ami(state, &amis, aws.monitoring_region, state.monitoring_architecture);
    const regions = try arena.alloc([]const u8, state.config.instances.len);
    for (state.config.instances, regions) |instance, *slot| {
        const architecture = state.type_info(instance.instance_type).architecture;
        _ = try find_ami(state, &amis, instance.region, architecture);
        slot.* = instance.region;
    }
    state.deployments = try arena.alloc(Deployment, state.config.instances.len);
    for (state.deployments, state.config.instances) |*deployment, *instance| {
        deployment.* = .{ .instance = instance };
    }
    var launcher: Launcher = .{ .state = state, .amis = amis.items };
    const io = state.session.io;
    const gpa = state.session.gpa;
    try create.run_launches(Launcher, io, gpa, &launcher, aws.monitoring_region, regions);
    log.info("instances requested", .{});
}

/// The newest Ubuntu AMI for `region` and `architecture`, looked up once each.
fn find_ami(
    state: *State,
    amis: *std.ArrayList(Ami),
    region: []const u8,
    architecture: Architecture,
) ![]const u8 {
    if (ami_of(amis.items, region, architecture)) |id| return id;
    const session = state.session;
    var regional = try session.ec2(region);
    const id = ec2_api.find_latest_ami(&regional, architecture) catch |err| {
        return session.ec2_failed(&regional, err);
    };
    log.info("selected AMI: region={s} architecture={f} ami_id={s}", .{ region, architecture, id });
    try amis.append(state.arena(), .{ .region = region, .architecture = architecture, .id = id });
    return id;
}

fn ami_of(amis: []const Ami, region: []const u8, architecture: Architecture) ?[]const u8 {
    for (amis) |ami| {
        if (ami.architecture == architecture and std.mem.eql(u8, ami.region, region)) return ami.id;
    }
    return null;
}

const Launcher = struct {
    state: *State,
    amis: []const Ami,

    pub const Error = anyerror;

    pub fn monitoring(launcher: *Launcher) Error!void {
        const state = launcher.state;
        const config = &state.config.monitoring;
        const region = state.region(aws.monitoring_region);
        const request: ec2_module.LaunchRequest = .{
            .ami_id = ami_of(launcher.amis, region.name, state.monitoring_architecture).?,
            .instance_type = config.instance_type,
            .storage_size = config.storage_size,
            .storage_class = try storage_class(state, aws.monitoring_name, config.storage_class),
            .storage_iops = config.storage_iops,
            .storage_throughput = config.storage_throughput,
            .bandwidth_weighting = config.bandwidth_weighting,
            .key_name = state.key_name,
            .sg_id = region.monitoring_sg_id.?,
            .count = 1,
            .name = aws.monitoring_name,
            .tag = state.config.tag,
        };
        const launched = try launch_one(state, region, &request, region.subnets, 0);
        state.monitoring_id = launched.instance_ids[0];
        log.info("launched monitoring instance: instance_id={s} az={s}", .{
            state.monitoring_id, launched.az,
        });
    }

    pub fn launch(launcher: *Launcher, index: usize) Error!void {
        const state = launcher.state;
        const instance = &state.config.instances[index];
        const region = state.region(instance.region);
        const architecture = state.type_info(instance.instance_type).architecture;
        const resources = region.resources();
        // Grouped instances get only their group's AZ, keeping a group colocated.
        const groups = state.groups;
        const subnets = try create.grouped_subnets(state.arena(), instance, &resources, groups);
        const request: ec2_module.LaunchRequest = .{
            .ami_id = ami_of(launcher.amis, region.name, architecture).?,
            .instance_type = instance.instance_type,
            .storage_size = instance.storage_size,
            .storage_class = try storage_class(state, instance.name, instance.storage_class),
            .storage_iops = instance.storage_iops,
            .storage_throughput = instance.storage_throughput,
            .bandwidth_weighting = instance.bandwidth_weighting,
            .key_name = state.key_name,
            .sg_id = region.binary_sg_id,
            .count = 1,
            .name = instance.name,
            .tag = state.config.tag,
        };
        // The instance's index spreads ungrouped instances across AZs.
        const launched = try launch_one(state, region, &request, subnets, index);
        state.deployments[index].id = launched.instance_ids[0];
        log.info("launched instance: instance_id={s} instance={s} az={s}", .{
            launched.instance_ids[0], instance.name, launched.az,
        });
    }
};

fn storage_class(state: *State, target: []const u8, name: []const u8) !ec2_module.VolumeType {
    return switch (ec2_module.parse_storage_class(target, name)) {
        .ok => |volume_type| volume_type,
        .failure => |failure| state.session.fail(failure),
    };
}

fn launch_one(
    state: *State,
    region: *const Region,
    request: *const ec2_module.LaunchRequest,
    subnets: []const create.Subnet,
    start_index: usize,
) !ec2_module.Launched {
    const session = state.session;
    const client = try session.client(region.name);
    const result = try ec2_module.launch_instances(
        client,
        session.gpa,
        session.arena,
        request,
        subnets,
        region.az_support,
        start_index,
    );
    return switch (result) {
        .ok => |launched| launched,
        .failure => |failure| session.fail(failure),
    };
}

/// Waits for every instance to run, then opens the binary groups to monitoring's scrapes
/// (before any instance is configured, so Prometheus never scrapes an unconfigured one).
fn wait_running(state: *State) !void {
    const session = state.session;
    var monitoring = try session.ec2(aws.monitoring_region);
    const ids: []const []const u8 = &.{state.monitoring_id};
    const ips = ec2_api.wait_for_instances_running(&monitoring, ids) catch |err| {
        return session.ec2_failed(&monitoring, err);
    };
    state.monitoring_ip = ips[0];
    for (state.regions) |*entry| try wait_region(state, entry);
    const monitoring_id = state.monitoring_id;
    state.monitoring_private_ip = ec2_api.get_private_ip(&monitoring, monitoring_id) catch |err| {
        return session.ec2_failed(&monitoring, err);
    };
    log.info("monitoring instance running: ip={s}", .{state.monitoring_ip});
    log.info("launched instances", .{});
    log.info("adding monitoring ingress rules", .{});
    for (state.regions) |entry| {
        var regional = try session.ec2(entry.name);
        const group = entry.binary_sg_id;
        ec2_api.add_monitoring_ingress(&regional, group, state.monitoring_ip) catch |err| {
            return session.ec2_failed(&regional, err);
        };
    }
    log.info("added monitoring ingress rules", .{});
}

/// Waits for a region's binary instances, `describe_batch_max` at a time.
fn wait_region(state: *State, entry: *const Region) !void {
    const session = state.session;
    const arena = state.arena();
    var members: std.ArrayList(*Deployment) = .empty;
    for (state.deployments) |*deployment| {
        if (!std.mem.eql(u8, deployment.instance.region, entry.name)) continue;
        try members.append(arena, deployment);
    }
    var regional = try session.ec2(entry.name);
    var start: usize = 0;
    while (start < members.items.len) {
        const chunk = members.items[start..@min(start + describe_batch_max, members.items.len)];
        const ids = try arena.alloc([]const u8, chunk.len);
        for (chunk, ids) |deployment, *id| id.* = deployment.id;
        const ips = ec2_api.wait_for_instances_running(&regional, ids) catch |err| {
            return session.ec2_failed(&regional, err);
        };
        assert(ips.len == chunk.len);
        for (chunk, ips) |deployment, ip| deployment.ip = ip;
        log.info("instances running in region: region={s} count={d}", .{ entry.name, chunk.len });
        start += chunk.len;
    }
}

// --- Configuration files -----------------------------------------------------------------------

/// The static configs every deployment shares, in commonware's order.
const statics = [_]struct { key: []const u8, text: []const u8 }{
    .{ .key = services.grafana_datasources_s3_key, .text = services.datasources_yml },
    .{ .key = services.grafana_dashboards_s3_key, .text = services.all_yml },
    .{ .key = services.loki_config_s3_key, .text = services.loki_config },
    .{ .key = services.pyroscope_config_s3_key, .text = services.pyroscope_config },
    .{ .key = services.tempo_config_s3_key, .text = services.tempo_config },
    .{ .key = services.pyroscope_agent_service_s3_key, .text = services.pyroscope_agent_service },
    .{ .key = services.pyroscope_agent_timer_s3_key, .text = services.pyroscope_agent_timer },
};

/// Uploads the shared and per-deployment configuration and builds each instance's URLs.
fn upload_configs(state: *State) !void {
    log.info("uploading config files to S3", .{});
    var urls: [statics.len][]const u8 = undefined;
    for (statics, &urls) |entry, *url| {
        url.* = try upload(state, entry.key, .{ .static = entry.text });
    }
    var unit_urls: std.EnumArray(Architecture, []const u8) = .initFill("");
    var iterator = state.architectures.iterator();
    while (iterator.next()) |architecture| {
        const key = services.binary_service_s3_key_for_arch(architecture);
        const unit = services.binary_service_unit;
        unit_urls.set(architecture, try upload(state, key, .{ .static = unit }));
    }
    const prometheus_url = try upload_prometheus(state);
    const dashboard_path = state.config.monitoring.dashboard;
    const io = state.session.io;
    const dashboard_digest = s3.hash_file(io, dashboard_path) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return state.session.fail(.{ .io = .{ .path = dashboard_path, .err = err } }),
    };
    const dashboard_key = try deployment_key(state, .monitoring, &dashboard_digest);
    const dashboard_url = try upload(state, dashboard_key, .{ .file = dashboard_path });
    const hosts_url = try upload_hosts(state);
    var uploads: std.ArrayList(Upload) = .empty;
    state.instance_urls = try state.arena().alloc(services.InstanceUrls, state.deployments.len);
    for (state.deployments, state.instance_urls) |*deployment, *out| {
        out.* = try instance_urls(state, &uploads, deployment, hosts_url, &urls, &unit_urls);
    }
    state.monitoring_urls = .{
        .docker_tgz = state.tools.get(state.monitoring_architecture).docker,
        .prometheus_config = prometheus_url,
        .datasources_yml = urls[0],
        .all_yml = urls[1],
        .dashboard = dashboard_url,
        .node_exporter_dashboard = state.node_exporter_dashboard_url,
        .loki_yml = urls[2],
        .pyroscope_yml = urls[3],
        .tempo_yml = urls[4],
        .images = try state.image_list(services.monitoring_images, state.monitoring_architecture),
    };
    log.info("uploaded config files to S3", .{});
}

/// The Prometheus configuration scraping every binary instance.
fn upload_prometheus(state: *State) ![]const u8 {
    const arena = state.arena();
    const targets = try arena.alloc(services.ScrapeTarget, state.deployments.len);
    for (state.deployments, targets) |deployment, *target| {
        const instance = deployment.instance;
        target.* = .{
            .name = instance.name,
            .ip = deployment.ip,
            .region = instance.region,
            .arch = state.type_info(instance.instance_type).architecture.as_str(),
        };
    }
    const scrape: []const services.ScrapeTarget = targets;
    const text = try written(arena, services.write_prometheus_config, .{scrape});
    const digest = sha256_hex(text);
    const path = try std.fs.path.join(arena, &.{ state.directory, "prometheus.yml" });
    try state.session.write_file(path, text);
    return upload(state, try deployment_key(state, .monitoring, &digest), .{ .static = text });
}

/// `hosts.yaml`, written locally (for `attach`) and shared by every instance.
fn upload_hosts(state: *State) ![]const u8 {
    const session = state.session;
    const arena = state.arena();
    const hosts_list = try arena.alloc(aws.Host, state.deployments.len);
    for (state.deployments, hosts_list) |deployment, *host| {
        host.* = .{
            .name = deployment.instance.name,
            .region = deployment.instance.region,
            .ip = try parse_ip(session, deployment.ip),
        };
    }
    const hosts: aws.Hosts = .{
        .monitoring = .{
            .public = try parse_ip(session, state.monitoring_ip),
            .private = try parse_ip(session, state.monitoring_private_ip),
        },
        .hosts = hosts_list,
    };
    var text: Io.Writer.Allocating = .init(arena);
    try hosts.write(&text.writer);
    const digest = sha256_hex(text.written());
    const parts = [_][]const u8{ state.directory, deployments_module.hosts_file_name };
    const path = try std.fs.path.join(arena, &parts);
    try session.write_file(path, text.written());
    return upload(state, try deployment_key(state, .hosts, &digest), .{ .static = text.written() });
}

fn parse_ip(session: *Session, text: []const u8) !IpAddr {
    return IpAddr.parse(text) catch session.fail(.ip_addr_parse);
}

/// One binary instance's URLs, uploading its promtail config and pyroscope script (once per
/// distinct content).
fn instance_urls(
    state: *State,
    uploads: *std.ArrayList(Upload),
    deployment: *const Deployment,
    hosts_url: []const u8,
    urls: *const [statics.len][]const u8,
    unit_urls: *const std.EnumArray(Architecture, []const u8),
) !services.InstanceUrls {
    const arena = state.arena();
    const instance = deployment.instance;
    const architecture = state.type_info(instance.instance_type).architecture;
    const arch = architecture.as_str();
    const private_ip = state.monitoring_private_ip;
    const args = .{ private_ip, instance.name, deployment.ip, instance.region, arch };
    const promtail = try written(arena, services.write_promtail_config, args);
    const promtail_name = try std.fmt.allocPrint(arena, "promtail_{s}.yml", .{instance.name});
    const pyroscope = try written(arena, services.write_pyroscope_script, args);
    const pyroscope_format = "pyroscope-agent_{s}.sh";
    const pyroscope_name = try std.fmt.allocPrint(arena, pyroscope_format, .{instance.name});
    const files = for (state.files) |entry| {
        if (std.mem.eql(u8, entry.name, instance.name)) break entry;
    } else unreachable; // Proof: `upload_instance_files` returns every instance's URLs.
    const tools = state.tools.get(architecture);
    return .{
        .binary = files.binary_url,
        .config = files.config_url,
        .hosts = hosts_url,
        .promtail_config = try upload_once(state, uploads, .promtail, promtail_name, promtail),
        .binary_service = unit_urls.get(architecture),
        .pyroscope_script = try upload_once(state, uploads, .pyroscope, pyroscope_name, pyroscope),
        .pyroscope_service = urls[5],
        .pyroscope_timer = urls[6],
        .docker_tgz = tools.docker,
        .logrotate_deb = tools.logrotate,
        .images = try state.image_list(services.binary_images, architecture),
    };
}

/// Writes `text` to `file_name` in the deployment directory and uploads it unless the same
/// content of `kind` was uploaded already.
fn upload_once(
    state: *State,
    uploads: *std.ArrayList(Upload),
    kind: DeploymentFile,
    file_name: []const u8,
    text: []const u8,
) ![]const u8 {
    const digest = sha256_hex(text);
    const path = try std.fs.path.join(state.arena(), &.{ state.directory, file_name });
    try state.session.write_file(path, text);
    for (uploads.items) |entry| {
        if (entry.kind == kind and std.mem.eql(u8, &entry.digest, &digest)) return entry.url;
    }
    const url = try upload(state, try deployment_key(state, kind, &digest), .{ .static = text });
    try uploads.append(state.arena(), .{ .kind = kind, .digest = digest, .url = url });
    return url;
}

fn deployment_key(state: *State, kind: DeploymentFile, digest: *const [64]u8) ![]const u8 {
    var key: Io.Writer.Allocating = .init(state.arena());
    try services.write_deployment_s3_key(&key.writer, state.config.tag, kind, digest);
    return key.written();
}

// --- Instance setup ----------------------------------------------------------------------------

/// Configures monitoring and, `concurrency` at a time, the binary instances.
fn configure(state: *State, concurrency: u64) !void {
    const io = state.session.io;
    log.info("configuring monitoring and binary instances", .{});
    const workers: usize = @intCast(@min(concurrency, state.deployments.len));
    const slots = try state.arena().alloc(?anyerror, workers + 1);
    @memset(slots, null);
    var pool: Pool = .{ .state = state };
    var group: Io.Group = .init;
    defer group.cancel(io);
    group.async(io, Pool.monitoring, .{ state, &slots[0] });
    for (slots[1..]) |*slot| group.async(io, Pool.work, .{ &pool, slot });
    try group.await(io);
    for (slots) |slot| if (slot) |err| return err;
    log.info("configured binary instances", .{});
}

const Pool = struct {
    state: *State,
    next: std.atomic.Value(usize) = .init(0),
    stopped: std.atomic.Value(bool) = .init(false),

    /// Takes binary instances until none remain or one fails.
    fn work(pool: *Pool, slot: *?anyerror) void {
        const state = pool.state;
        while (!pool.stopped.load(.acquire)) {
            const index = pool.next.fetchAdd(1, .acq_rel);
            if (index >= state.deployments.len) return;
            const deployment = &state.deployments[index];
            configure_binary(state, deployment, &state.instance_urls[index]) catch |err| {
                slot.* = err;
                pool.stopped.store(true, .release);
                return;
            };
        }
    }

    fn monitoring(state: *State, slot: *?anyerror) void {
        configure_monitoring(state) catch |err| {
            slot.* = err;
        };
    }
};

fn configure_binary(
    state: *State,
    deployment: *const Deployment,
    urls: *const services.InstanceUrls,
) !void {
    const session = state.session;
    const arena = state.arena();
    const instance = deployment.instance;
    const ip = deployment.ip;
    var regional = try session.ec2(instance.region);
    ec2_api.wait_for_instances_ready(&regional, &.{deployment.id}) catch |err| {
        return session.ec2_failed(&regional, err);
    };
    try execute(state, ip, services.disable_automatic_apt_upgrades_cmd);
    const nvme = state.type_info(instance.instance_type).nvme;
    var apt: Io.Writer.Allocating = .init(arena);
    if (try services.write_install_binary_apt_cmd(&apt.writer, instance.profiling, nvme)) {
        try execute(state, ip, apt.written());
    }
    if (nvme) try execute(state, ip, try written(arena, services.write_nvme_setup_cmd, .{}));
    try execute(state, ip, try written(arena, services.write_install_binary_download_cmd, .{urls}));
    const profiling = instance.profiling;
    const setup = try written(arena, services.write_install_binary_setup_cmd, .{profiling});
    try execute(state, ip, setup);
    try poll(state, ip, "binary");
    for (services.binary_image_service_names) |service| try poll(state, ip, service);
    log.info("configured instance: ip={s} instance={s}", .{ ip, instance.name });
}

fn configure_monitoring(state: *State) !void {
    const session = state.session;
    const arena = state.arena();
    const ip = state.monitoring_ip;
    var monitoring = try session.ec2(aws.monitoring_region);
    ec2_api.wait_for_instances_ready(&monitoring, &.{state.monitoring_id}) catch |err| {
        return session.ec2_failed(&monitoring, err);
    };
    try execute(state, ip, services.disable_automatic_apt_upgrades_cmd);
    const urls = &state.monitoring_urls;
    const download = try written(arena, services.write_install_monitoring_download_cmd, .{urls});
    try execute(state, ip, download);
    try execute(state, ip, try written(arena, services.write_install_monitoring_setup_cmd, .{}));
    try execute(state, ip, try written(arena, services.write_start_monitoring_services_cmd, .{}));
    for (services.monitoring_image_service_names) |service| try poll(state, ip, service);
    log.info("configured monitoring instance: ip={s}", .{ip});
}

fn execute(state: *State, ip: []const u8, command: []const u8) !void {
    const session = state.session;
    session.remote.execute(state.private_key, ip, command) catch |err| {
        return session.remote_failed(err, ip, "ssh");
    };
}

fn poll(state: *State, ip: []const u8, service: []const u8) !void {
    const session = state.session;
    session.remote.poll(state.private_key, ip, service, .active) catch |err| {
        return session.remote_failed(err, ip, service);
    };
}

/// Opens monitoring's logs, profiles, and traces ports to the binary instances: by security
/// group in the monitoring region, by VPC CIDR in the others.
fn link_monitoring(state: *State) !void {
    const session = state.session;
    log.info("updating monitoring security group to allow traffic from binary instances", .{});
    var monitoring = try session.ec2(aws.monitoring_region);
    const home = state.region(aws.monitoring_region);
    const group = home.monitoring_sg_id.?;
    if (home.has_binaries) {
        const source: ec2_api.MonitoringSource = .{ .group = home.binary_sg_id };
        ec2_api.authorize_monitoring_ports(&monitoring, group, source) catch |err| {
            return session.ec2_failed(&monitoring, err);
        };
        log.info("linked monitoring and binary security groups in monitoring region", .{});
    }
    for (state.regions) |entry| {
        if (entry.index == home.index or !entry.has_binaries) continue;
        const source: ec2_api.MonitoringSource = .{ .cidr = entry.vpc_cidr };
        ec2_api.authorize_monitoring_ports(&monitoring, group, source) catch |err| {
            return session.ec2_failed(&monitoring, err);
        };
        log.info("opened monitoring port to traffic from binary VPC: region={s}", .{entry.name});
    }
    log.info("updated monitoring security group", .{});
}

// --- Helpers -----------------------------------------------------------------------------------

/// What `write(writer, args...)` writes, allocated from `arena`.
fn written(arena: Allocator, comptime write: anytype, args: anytype) ![]const u8 {
    var out: Io.Writer.Allocating = .init(arena);
    try @call(.auto, write, .{&out.writer} ++ args);
    return out.written();
}

fn sha256_hex(data: []const u8) [64]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &hash, .{});
    return std.fmt.bytesToHex(hash, .lower);
}

fn contains(items: []const []const u8, wanted: []const u8) bool {
    for (items) |item| if (std.mem.eql(u8, item, wanted)) return true;
    return false;
}

fn append_distinct(arena: Allocator, list: *std.ArrayList([]const u8), item: []const u8) !void {
    if (!contains(list.items, item)) try list.append(arena, item);
}

fn less_than(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

test {
    _ = @import("create_flow_test.zig");
}
