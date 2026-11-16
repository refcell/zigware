//! The Bulletproofs inner product argument (commonware `zk/bulletproofs/ipa.rs`).
//!
//! A prover holds vectors `a_i`, `b_i` over the scalar field `F` of a group `G`, and a
//! commitment `P = <a_i, G_i> + <b_i, y^i H_i>`. The argument convinces a verifier that the
//! committed vectors have inner product `c = <a_i, b_i>` while sending `O(lg N)` group
//! elements. It is not zero-knowledge by itself; it is a step in larger proof systems.
//!
//! - `Setup(G)` holds the generators `G_i`, `H_i`, and the product generator `Q`.
//! - `Witness(F)` holds `a_i` and `b_i` (equal power-of-two lengths); `init_with_claim`
//!   also computes the matching `Claim(F, G)`.
//! - `prove` builds a `Proof(F, G)` bound to a `Transcript`'s state, and `verify` replays
//!   the same transcript and returns a `Synthetic` equation over a virtual setup that is zero
//!   for a valid proof. `Setup.eval` builds the virtual setup, runs `verify` through a
//!   callback, and evaluates the equation against the concrete generators.
//!
//! Wire formats match commonware byte for byte. Rust's `FnOnce` callback for `eval` becomes a
//! comptime function taking a context; `prove` and `verify` borrow their witness and proof.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const codec = @import("codec");
const math = @import("math");
const parallel = @import("parallel");
const transcript_module = @import("../../transcript.zig");

const algebra = math.algebra;
const Synthetic = math.synthetic.Synthetic;
const Transcript = transcript_module.Transcript;
pub const Summary = transcript_module.Summary;

/// The generators `G_i`, `H_i` (always as many of each) and the product generator `Q`. The
/// generators must have no known discrete logarithm relations to each other.
pub fn Setup(comptime G: type) type {
    return struct {
        const Self = @This();

        g: []G,
        h: []G,
        product_generator: G,

        /// The most generator pairs to accept, and the group element config.
        pub const Cfg = struct { usize, codec.Cfg(G) };

        /// A setup from `Q` and the `(G_i, H_i)` pairs (Rust's `Setup::new`), copying them.
        pub fn init(gpa: Allocator, product_generator: G, pairs: []const [2]G) !Self {
            const g = try gpa.alloc(G, pairs.len);
            errdefer gpa.free(g);
            const h = try gpa.alloc(G, pairs.len);
            for (pairs, g, h) |pair, *g_i, *h_i| {
                g_i.* = pair[0];
                h_i.* = pair[1];
            }
            return .{ .g = g, .h = h, .product_generator = product_generator };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            assert(self.g.len == self.h.len);
            if (comptime @hasDecl(G, "deinit")) {
                for (self.g) |*g_i| g_i.deinit(gpa);
                for (self.h) |*h_i| h_i.deinit(gpa);
                self.product_generator.deinit(gpa);
            }
            gpa.free(self.g);
            gpa.free(self.h);
            self.* = undefined;
        }

        /// Whether the setup has enough generators for vectors of length `2^lg_len`.
        pub fn supports(self: Self, lg_len: u8) bool {
            if (lg_len >= @bitSizeOf(usize)) return false;
            return self.g.len >> @intCast(lg_len) > 0;
        }

        /// The virtual setup `eval` binds: generator indices `0..n` stand for `G_i`, `n..2n`
        /// for `H_i`, and `2n` for `Q`.
        pub fn virtual_setup(
            self: Self,
            gpa: Allocator,
            comptime F: type,
        ) !Setup(Synthetic(F, G)) {
            const S = Synthetic(F, G);
            const n = self.g.len;
            assert(n == self.h.len);
            const g = try gpa.alloc(S, n);
            errdefer gpa.free(g);
            const h = try gpa.alloc(S, n);
            errdefer gpa.free(h);
            @memset(g, S.zero);
            @memset(h, S.zero);
            errdefer for (g, h) |*g_i, *h_i| {
                g_i.deinit(gpa);
                h_i.deinit(gpa);
            };
            for (g, 0..) |*g_i, i| g_i.* = try S.generator(gpa, @intCast(i));
            for (h, 0..) |*h_i, i| h_i.* = try S.generator(gpa, @intCast(n + i));
            const q = try S.generator(gpa, @intCast(2 * n));
            return .{ .g = g, .h = h, .product_generator = q };
        }

        /// The concrete generators in virtual-index order: `G_i`, then `H_i`, then `Q`.
        pub fn flatten(self: Self, gpa: Allocator) ![]G {
            const n = self.g.len;
            const flat = try gpa.alloc(G, 2 * n + 1);
            @memcpy(flat[0..n], self.g);
            @memcpy(flat[n .. 2 * n], self.h);
            flat[2 * n] = self.product_generator;
            return flat;
        }

        /// Builds the virtual setup, calls `f(context, gpa, &virtual)` for a verification
        /// equation, and evaluates it against these generators. Null when `f` returns null
        /// (a malformed proof); otherwise zero means the proof verified.
        pub fn eval(
            self: Self,
            gpa: Allocator,
            comptime F: type,
            context: anytype,
            comptime f: anytype,
        ) !?G {
            var virtual = try self.virtual_setup(gpa, F);
            defer virtual.deinit(gpa);
            var equation = (try f(context, gpa, &virtual)) orelse return null;
            defer equation.deinit(gpa);
            const flat = try self.flatten(gpa);
            defer gpa.free(flat);
            return try equation.eval(gpa, flat);
        }

        pub fn eql(a: Self, b: Self) bool {
            if (a.g.len != b.g.len or !a.product_generator.eql(b.product_generator)) return false;
            for (a.g, a.h, b.g, b.h) |ag, ah, bg, bh| {
                if (!ag.eql(bg) or !ah.eql(bh)) return false;
            }
            return true;
        }

        pub fn encode_size(self: Self) usize {
            var size = codec.encode_size(G, self.product_generator);
            size += codec.encode_size(usize, self.g.len);
            for (self.g, self.h) |g_i, h_i| {
                size += codec.encode_size(G, g_i) + codec.encode_size(G, h_i);
            }
            return size;
        }

        /// `Q`, the pair count, then each `G_i, H_i` interleaved.
        pub fn write(self: Self, writer: *codec.Writer) void {
            assert(self.g.len == self.h.len);
            codec.write(G, self.product_generator, writer);
            codec.write(usize, self.g.len, writer);
            for (self.g, self.h) |g_i, h_i| {
                codec.write(G, g_i, writer);
                codec.write(G, h_i, writer);
            }
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            comptime assert(!codec.owns_memory(G));
            const product_generator = try codec.read_cfg(G, gpa, reader, cfg[1]);
            const len = try codec.read_usize(reader, codec.RangeCfg(usize).to_inclusive(cfg[0]));
            if (comptime codec.fixed_size(G)) |size| try reader.at_least_items(len, 2 * size);
            const g = try gpa.alloc(G, len);
            errdefer gpa.free(g);
            const h = try gpa.alloc(G, len);
            errdefer gpa.free(h);
            for (g, h) |*g_i, *h_i| {
                g_i.* = try codec.read_cfg(G, gpa, reader, cfg[1]);
                h_i.* = try codec.read_cfg(G, gpa, reader, cfg[1]);
            }
            return .{ .g = g, .h = h, .product_generator = product_generator };
        }
    };
}

/// The public statement: `commitment = <a_i, G_i> + <b_i, y^i H_i>`, `product = <a_i, b_i>`,
/// for vectors of length `2^log_len`.
pub fn Claim(comptime F: type, comptime G: type) type {
    return struct {
        const Self = @This();

        commitment: G,
        product: F,
        y: F,
        log_len: u8,

        pub const Cfg = struct { codec.Cfg(G), codec.Cfg(F) };

        pub fn eql(a: Self, b: Self) bool {
            return a.commitment.eql(b.commitment) and a.product.eql(b.product) and
                a.y.eql(b.y) and a.log_len == b.log_len;
        }

        pub fn encode_size(self: Self) usize {
            return codec.encode_size(G, self.commitment) + codec.encode_size(F, self.product) +
                codec.encode_size(F, self.y) + 1;
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write(G, self.commitment, writer);
            codec.write(F, self.product, writer);
            codec.write(F, self.y, writer);
            codec.write(u8, self.log_len, writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            comptime assert(!codec.owns_memory(G) and !codec.owns_memory(F));
            return .{
                .commitment = try codec.read_cfg(G, gpa, reader, cfg[0]),
                .product = try codec.read_cfg(F, gpa, reader, cfg[1]),
                .y = try codec.read_cfg(F, gpa, reader, cfg[1]),
                .log_len = try codec.read(u8, gpa, reader),
            };
        }
    };
}

/// The vectors `a_i` and `b_i`, of equal power-of-two length.
pub fn Witness(comptime F: type) type {
    return struct {
        const Self = @This();

        a: []F,
        b: []F,

        /// Copies `a` and `b` (equal lengths); null unless the length is a power of two.
        pub fn init(gpa: Allocator, a: []const F, b: []const F) !?Self {
            assert(a.len == b.len);
            if (a.len == 0 or !std.math.isPowerOfTwo(a.len)) return null;
            const a_copy = try gpa.dupe(F, a);
            errdefer gpa.free(a_copy);
            return .{ .a = a_copy, .b = try gpa.dupe(F, b) };
        }

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.a);
            gpa.free(self.b);
            self.* = undefined;
        }

        /// Like `init`, also computing the honest claim (Rust's `new_with_claim`). Null when
        /// the length is not a power of two or the setup is too short.
        pub fn init_with_claim(
            comptime G: type,
            gpa: Allocator,
            setup: *const Setup(G),
            y: F,
            a: []const F,
            b: []const F,
        ) !?struct { Self, Claim(F, G) } {
            comptime assert(G.Scalar == F);
            var witness = (try init(gpa, a, b)) orelse return null;
            if (setup.g.len < witness.a.len) {
                witness.deinit(gpa);
                return null;
            }
            var commitment = G.zero;
            var product = F.zero;
            var y_powers = algebra.powers(F, F.one, y);
            for (witness.a, witness.b, setup.g[0..a.len], setup.h[0..a.len]) |a_i, b_i, g_i, h_i| {
                const y_i = y_powers.next();
                commitment = commitment.add(g_i.mul(a_i).add(h_i.mul(b_i.mul(y_i))));
                product = product.add(a_i.mul(b_i));
            }
            const log_len: u8 = @intCast(std.math.log2_int(usize, witness.a.len));
            const claim: Claim(F, G) = .{
                .commitment = commitment,
                .product = product,
                .y = y,
                .log_len = log_len,
            };
            return .{ witness, claim };
        }
    };
}

/// An inner product proof: the `(L, R)` commitments of each folding round, the transcript
/// summary after them (binding even zero-round proofs), and the final scalars.
pub fn Proof(comptime F: type, comptime G: type) type {
    return struct {
        const Self = @This();

        l_r_coms: [][2]G,
        transcript_summary: Summary,
        a_final: F,
        b_final: F,

        /// The largest vector length to accept (bounding the rounds by its log), and the
        /// group and field configs.
        pub const Cfg = struct { usize, struct { codec.Cfg(G), codec.Cfg(F) } };

        pub fn deinit(self: *Self, gpa: Allocator) void {
            gpa.free(self.l_r_coms);
            self.* = undefined;
        }

        pub fn clone(self: Self, gpa: Allocator) !Self {
            var out = self;
            out.l_r_coms = try gpa.dupe([2]G, self.l_r_coms);
            return out;
        }

        pub fn eql(a: Self, b: Self) bool {
            if (a.l_r_coms.len != b.l_r_coms.len) return false;
            for (a.l_r_coms, b.l_r_coms) |x, y| {
                if (!x[0].eql(y[0]) or !x[1].eql(y[1])) return false;
            }
            return a.transcript_summary.eql(b.transcript_summary) and
                a.a_final.eql(b.a_final) and a.b_final.eql(b.b_final);
        }

        pub fn encode_size(self: Self) usize {
            return codec.encode_size([]const [2]G, self.l_r_coms) + Summary.fixed_size +
                codec.encode_size(F, self.a_final) + codec.encode_size(F, self.b_final);
        }

        pub fn write(self: Self, writer: *codec.Writer) void {
            codec.write([]const [2]G, self.l_r_coms, writer);
            codec.write(Summary, self.transcript_summary, writer);
            codec.write(F, self.a_final, writer);
            codec.write(F, self.b_final, writer);
        }

        pub fn read(gpa: Allocator, reader: *codec.Reader, cfg: Cfg) codec.Error!Self {
            comptime assert(!codec.owns_memory(G) and !codec.owns_memory(F));
            const max_rounds: usize = if (cfg[0] == 0) 0 else std.math.log2_int(usize, cfg[0]);
            const ItemsCfg = codec.Cfg([]const [2]G);
            var items_cfg: ItemsCfg = undefined;
            items_cfg.range = codec.RangeCfg(usize).to_inclusive(max_rounds);
            items_cfg.item = cfg[1][0];
            const l_r_coms = try codec.read_cfg([]const [2]G, gpa, reader, items_cfg);
            errdefer gpa.free(l_r_coms);
            return .{
                .l_r_coms = @constCast(l_r_coms),
                .transcript_summary = try codec.read(Summary, gpa, reader),
                .a_final = try codec.read_cfg(F, gpa, reader, cfg[1][1]),
                .b_final = try codec.read_cfg(F, gpa, reader, cfg[1][1]),
            };
        }
    };
}

/// Commits the encoding of `value` to `transcript`.
fn commit_encoded(comptime T: type, gpa: Allocator, transcript: *Transcript, value: T) !void {
    const bytes = try codec.encode(T, gpa, value);
    defer gpa.free(bytes);
    transcript.commit(bytes);
}

/// A field element drawn from the transcript's noise under `label`.
fn challenge(comptime F: type, transcript: *const Transcript, label: []const u8) F {
    var noise = transcript.noise(label);
    return F.random(&noise);
}

/// `2^log_len`, or null when it does not fit a `usize` (Rust's `checked_shl`).
fn claimed_length(log_len: u8) ?usize {
    if (log_len >= @bitSizeOf(usize)) return null;
    return @as(usize, 1) << @intCast(log_len);
}

/// Proves `witness` against `claim` and `setup`, bound to the current transcript state. Null
/// when the setup is too short or the claimed length differs from the witness length.
pub fn prove(
    comptime G: type,
    gpa: Allocator,
    transcript: *Transcript,
    setup: *const Setup(G),
    claim: Claim(G.Scalar, G),
    witness: *const Witness(G.Scalar),
    strategy: anytype,
) !?Proof(G.Scalar, G) {
    const F = G.Scalar;
    comptime algebra.assert_crypto_group(G);
    comptime parallel.assert_strategy(@TypeOf(strategy));
    const n = witness.a.len;
    assert(n == witness.b.len);
    const claimed_len = claimed_length(claim.log_len) orelse return null;
    if (claimed_len != n or setup.g.len < n) return null;
    // Committing to the claim first stops it from depending on the challenges.
    try commit_encoded(Claim(F, G), gpa, transcript, claim);
    const w = challenge(F, transcript, "w challenge");
    const w_q = setup.product_generator.mul(w);

    const a = try gpa.dupe(F, witness.a);
    defer gpa.free(a);
    const b = try gpa.dupe(F, witness.b);
    defer gpa.free(b);
    const g = try gpa.dupe(G, setup.g[0..n]);
    defer gpa.free(g);
    const h = try gpa.dupe(G, setup.h[0..n]);
    defer gpa.free(h);
    var y_powers = algebra.powers(F, F.one, claim.y);
    for (h) |*h_i| h_i.* = h_i.mul(y_powers.next());

    const l_r_coms = try gpa.alloc([2]G, claim.log_len);
    errdefer gpa.free(l_r_coms);
    var len = n;
    var round: usize = 0;
    while (len > 1) : (round += 1) {
        const l_r = round_commitments(G, a[0..len], b[0..len], g[0..len], h[0..len], w_q);
        l_r_coms[round] = l_r;
        try commit_encoded(G, gpa, transcript, l_r[0]);
        try commit_encoded(G, gpa, transcript, l_r[1]);
        const u = challenge(F, transcript, "u challenge");
        const u_inv = u.inv();
        const mid = len / 2;
        for (a[0..mid], a[mid..len]) |*lo, hi| lo.* = lo.mul(u).add(u_inv.mul(hi));
        for (b[0..mid], b[mid..len]) |*lo, hi| lo.* = lo.mul(u_inv).add(u.mul(hi));
        fold_generators(G, strategy, g[0..len], h[0..len], u, u_inv);
        len = mid;
    }
    assert(round == claim.log_len and len == 1);
    return .{
        .l_r_coms = l_r_coms,
        .transcript_summary = transcript.summarize(),
        .a_final = a[0],
        .b_final = b[0],
    };
}

/// One round's `L = <a_lo, G_hi> + <b_hi, H_lo> + <a_lo, b_hi> wQ` and
/// `R = <a_hi, G_lo> + <b_lo, H_hi> + <a_hi, b_lo> wQ`.
fn round_commitments(
    comptime G: type,
    a: []const G.Scalar,
    b: []const G.Scalar,
    g: []const G,
    h: []const G,
    w_q: G,
) [2]G {
    const F = G.Scalar;
    const mid = a.len / 2;
    assert(mid > 0 and b.len == a.len and g.len == a.len and h.len == a.len);
    const l = algebra.msm(G, F, g[mid..], a[0..mid])
        .add(algebra.msm(G, F, h[0..mid], b[mid..]))
        .add(w_q.mul(algebra.msm(F, F, a[0..mid], b[mid..])));
    const r = algebra.msm(G, F, g[0..mid], a[mid..])
        .add(algebra.msm(G, F, h[mid..], b[0..mid]))
        .add(w_q.mul(algebra.msm(F, F, a[mid..], b[0..mid])));
    return .{ l, r };
}

/// `out[i] = x[i] u + y[i] u^-1`; `out` may alias `x` or `y` (each index reads only itself).
fn Fold(comptime G: type) type {
    return struct {
        x: []const G,
        y: []const G,
        u: G.Scalar,
        u_inv: G.Scalar,

        pub fn map(op: @This(), index: usize) G {
            return op.x[index].mul(op.u).add(op.y[index].mul(op.u_inv));
        }
    };
}

fn FoldJob(comptime G: type, comptime S: type) type {
    return struct {
        strategy: S,
        out: []G,
        op: Fold(G),

        pub fn call(job: @This()) void {
            job.strategy.map_into(parallel.Range.upto(job.out.len), job.out, job.op);
        }
    };
}

/// Halves the generators in place: `G' = u^-1 G_lo + u G_hi`, `H' = u H_lo + u^-1 H_hi`.
fn fold_generators(
    comptime G: type,
    strategy: anytype,
    g: []G,
    h: []G,
    u: G.Scalar,
    u_inv: G.Scalar,
) void {
    const mid = g.len / 2;
    assert(mid > 0 and h.len == g.len);
    const Job = FoldJob(G, @TypeOf(strategy));
    const g_job: Job = .{
        .strategy = strategy,
        .out = g[0..mid],
        .op = .{ .x = g[mid..], .y = g[0..mid], .u = u, .u_inv = u_inv },
    };
    const h_job: Job = .{
        .strategy = strategy,
        .out = h[0..mid],
        .op = .{ .x = h[0..mid], .y = h[mid..], .u = u, .u_inv = u_inv },
    };
    _ = strategy.join(g_job, h_job);
}

/// Builds the equation for `proof` against `claim` and a virtual `setup` (see `Setup.eval`),
/// replaying the transcript. It evaluates to zero exactly when the proof is valid. Null when
/// the proof is malformed: the wrong round count, a transcript mismatch, or (where commonware
/// would panic) a setup shorter than the claimed length.
pub fn verify(
    comptime G: type,
    gpa: Allocator,
    transcript: *Transcript,
    setup: *const Setup(Synthetic(G.Scalar, G)),
    claim: Claim(G.Scalar, G),
    proof: Proof(G.Scalar, G),
) !?Synthetic(G.Scalar, G) {
    const F = G.Scalar;
    const S = Synthetic(F, G);
    comptime algebra.assert_crypto_group(G);
    const claimed_len = claimed_length(claim.log_len) orelse return null;
    const rounds: usize = claim.log_len;
    if (proof.l_r_coms.len != rounds or setup.g.len < claimed_len) return null;
    try commit_encoded(Claim(F, G), gpa, transcript, claim);
    const w = challenge(F, transcript, "w challenge");

    // The equation, which must be zero: commitment + c w Q + sum(u_k^2 L_k + u_k^-2 R_k)
    //   - a <g_weights, G> - b <h_weights, H> - a b w Q.
    const us = try gpa.alloc([2]F, rounds);
    defer gpa.free(us);
    const terms = try gpa.alloc(S.ConcreteTerm, 2 * rounds + 1);
    defer gpa.free(terms);
    for (proof.l_r_coms, us, 0..) |l_r, *u_pair, round| {
        try commit_encoded(G, gpa, transcript, l_r[0]);
        try commit_encoded(G, gpa, transcript, l_r[1]);
        const u = challenge(F, transcript, "u challenge");
        const u_inv = u.inv();
        u_pair.* = .{ u, u_inv };
        terms[2 * round] = .{ .weight = u.mul(u), .point = l_r[0] };
        terms[2 * round + 1] = .{ .weight = u_inv.mul(u_inv), .point = l_r[1] };
    }
    if (!transcript.summarize().eql(proof.transcript_summary)) return null;
    terms[2 * rounds] = .{ .weight = F.one, .point = claim.commitment };
    var out = try S.init_concrete(gpa, terms);
    errdefer out.deinit(gpa);
    const q = setup.product_generator;
    try add_scaled(S, gpa, &out, q, claim.product.mul(w), .add);
    try subtract_final(G, gpa, &out, setup, claim, proof, us);
    try add_scaled(S, gpa, &out, q, proof.a_final.mul(proof.b_final).mul(w), .sub);
    return out;
}

/// Subtracts `b <h_weights, H> + a <g_weights, G>`, the folded generators expressed in the
/// original ones.
fn subtract_final(
    comptime G: type,
    gpa: Allocator,
    out: *Synthetic(G.Scalar, G),
    setup: *const Setup(Synthetic(G.Scalar, G)),
    claim: Claim(G.Scalar, G),
    proof: Proof(G.Scalar, G),
    us: []const [2]G.Scalar,
) !void {
    const F = G.Scalar;
    const S = Synthetic(F, G);
    const len = @as(usize, 1) << @intCast(us.len);
    const g_weights = try fold_weights(F, gpa, us);
    defer gpa.free(g_weights);
    // H's weights are G's reversed (u and u^-1 swap sides), times y^i for H'_i = y^i H_i.
    const h_weights = try gpa.alloc(F, len);
    defer gpa.free(h_weights);
    var y_powers = algebra.powers(F, F.one, claim.y);
    for (h_weights, 0..) |*h_i, i| h_i.* = y_powers.next().mul(g_weights[len - 1 - i]);
    var h_sum = try synthetic_msm(S, gpa, setup.h[0..len], h_weights);
    defer h_sum.deinit(gpa);
    h_sum.mul_assign(proof.b_final);
    try out.sub_assign(gpa, h_sum);
    var g_sum = try synthetic_msm(S, gpa, setup.g[0..len], g_weights);
    defer g_sum.deinit(gpa);
    g_sum.mul_assign(proof.a_final);
    try out.sub_assign(gpa, g_sum);
}

/// The weights expressing the fully folded `G_0` in the original `G_i`: start from `[1]`, and
/// for each round from last to first, double the list, scaling the left half by `u^-1` and the
/// right half by `u`.
fn fold_weights(comptime F: type, gpa: Allocator, us: []const [2]F) ![]F {
    const len = @as(usize, 1) << @intCast(us.len);
    const weights = try gpa.alloc(F, len);
    weights[0] = F.one;
    var filled: usize = 1;
    var round = us.len;
    while (round > 0) {
        round -= 1;
        const u, const u_inv = us[round];
        @memcpy(weights[filled .. 2 * filled], weights[0..filled]);
        for (weights[0..filled]) |*left| left.* = left.mul(u_inv);
        for (weights[filled .. 2 * filled]) |*right| right.* = right.mul(u);
        filled *= 2;
    }
    assert(filled == len);
    return weights;
}

/// `out += point * weight` (or `-=`) for a synthetic `point`.
pub fn add_scaled(
    comptime S: type,
    gpa: Allocator,
    out: *S,
    point: S,
    weight: anytype,
    comptime sign: enum { add, sub },
) !void {
    var scaled = try point.clone(gpa);
    defer scaled.deinit(gpa);
    scaled.mul_assign(weight);
    switch (sign) {
        .add => try out.add_assign(gpa, scaled),
        .sub => try out.sub_assign(gpa, scaled),
    }
}

/// `sum_i points[i] * weights[i]` over synthetic points (`Synthetic::msm`).
pub fn synthetic_msm(comptime S: type, gpa: Allocator, points: []const S, weights: anytype) !S {
    assert(points.len == weights.len);
    var out: S = .zero;
    errdefer out.deinit(gpa);
    for (points, weights) |point, weight| try add_scaled(S, gpa, &out, point, weight, .add);
    return out;
}
