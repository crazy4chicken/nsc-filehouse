// Package config loads the filewarehouse runtime configuration.
//
// Precedence: command line flag > FILEWAREHOUSE_* environment variable > Nekostick
// HOST/PORT environment variable > built-in default.
package config

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment variable names. FILEWAREHOUSE_* wins over HOST/PORT.
const (
	EnvDSN              = "FILEWAREHOUSE_DSN"
	EnvAddr             = "FILEWAREHOUSE_ADDR"
	EnvPort             = "FILEWAREHOUSE_PORT"
	EnvBlobDir          = "FILEWAREHOUSE_BLOB_DIR"
	EnvKeyDir           = "FILEWAREHOUSE_KEY_DIR"
	EnvLogLevel         = "FILEWAREHOUSE_LOG_LEVEL"
	EnvNodeID           = "FILEWAREHOUSE_NODE_ID"
	EnvPublicBaseURL    = "FILEWAREHOUSE_PUBLIC_BASE_URL"
	EnvTrustedProxies   = "FILEWAREHOUSE_TRUSTED_PROXIES"
	EnvTeamusersBaseURL = "FILEWAREHOUSE_TEAMUSERS_BASE_URL"
	EnvTeamusersIssuer  = "FILEWAREHOUSE_TEAMUSERS_ISSUER"
	EnvTeamusersAud     = "FILEWAREHOUSE_TEAMUSERS_AUDIENCE"
	EnvTeamusersToken   = "FILEWAREHOUSE_TEAMUSERS_SERVICE_TOKEN"
	EnvTeamusersClient  = "FILEWAREHOUSE_TEAMUSERS_CLIENT_ID"
	EnvTeamusersSecret  = "FILEWAREHOUSE_TEAMUSERS_CLIENT_SECRET"
	EnvTeamusersNATS    = "FILEWAREHOUSE_TEAMUSERS_NATS_URL"
	EnvTeamusersTimeout = "FILEWAREHOUSE_TEAMUSERS_TIMEOUT"
	// EnvTeamusersAdminToken carries the teamusers admin token used by the
	// register-permissions subcommand.
	EnvTeamusersAdminToken = "FILEWAREHOUSE_TEAMUSERS_ADMIN_TOKEN"
	EnvPresignDefaultTTL   = "FILEWAREHOUSE_PRESIGN_DEFAULT_TTL"
	EnvPresignMaxTTL       = "FILEWAREHOUSE_PRESIGN_MAX_TTL"
	EnvObjectMaxBytes      = "FILEWAREHOUSE_OBJECT_MAX_BYTES"
	EnvPartMaxBytes        = "FILEWAREHOUSE_PART_MAX_BYTES"
	EnvUploadTTL           = "FILEWAREHOUSE_UPLOAD_TTL"
	EnvBucketQuotaBytes    = "FILEWAREHOUSE_BUCKET_DEFAULT_QUOTA_BYTES"
	EnvBucketQuotaObjects  = "FILEWAREHOUSE_BUCKET_DEFAULT_QUOTA_OBJECTS"
	EnvGCInterval          = "FILEWAREHOUSE_GC_INTERVAL"
	EnvGCGrace             = "FILEWAREHOUSE_GC_GRACE"
	EnvIdempotencyTTL      = "FILEWAREHOUSE_IDEMPOTENCY_TTL"

	// EnvFallbackHost and EnvFallbackPort are the Nekostick fleet fallbacks for
	// the listener.
	EnvFallbackHost = "HOST"
	EnvFallbackPort = "PORT"
)

// Defaults applied when neither a flag nor an environment variable is present.
const (
	DefaultAddr                  = "127.0.0.1"
	DefaultPort                  = 8080
	DefaultBlobDir               = "data"
	DefaultKeyDir                = "data/keys"
	DefaultLogLevel              = "info"
	DefaultIAMTimeout            = 5 * time.Second
	DefaultPresignTTL            = 15 * time.Minute
	DefaultPresignMaxTTL         = 24 * time.Hour
	DefaultObjectMaxBytes        = int64(5) << 30
	DefaultPartMaxBytes          = int64(256) << 20
	DefaultUploadTTL             = 24 * time.Hour
	DefaultGCInterval            = 15 * time.Minute
	DefaultGCGrace               = time.Hour
	DefaultIdempotencyTTL        = 24 * time.Hour
	DefaultBucketDefaultQuotaVal = int64(0)
)

// Config is the complete runtime configuration.
type Config struct {
	ConnectionString string
	ListenAddress    string
	ListenPort       int
	BlobDir          string
	KeyDir           string
	LogLevel         string
	NodeID           string
	// PublicBaseURL is the absolute origin used to build presigned links. Empty
	// derives it from the incoming request; a trailing slash is trimmed by
	// Validate so the value can be joined verbatim.
	PublicBaseURL  string
	TrustedProxies []netip.Prefix
	IAM            IAMConfig
	Presign        PresignConfig
	Limits         LimitsConfig
	GC             GCConfig
	IdempotencyTTL time.Duration
}

// IAMConfig describes the teamusers IAM service this instance talks to.
type IAMConfig struct {
	BaseURL      string
	Issuer       string
	Audience     string
	ServiceToken string
	ClientID     string
	ClientSecret string
	NATSURL      string
	Timeout      time.Duration
}

// PresignConfig bounds presigned URL lifetimes.
type PresignConfig struct {
	DefaultTTL time.Duration
	MaxTTL     time.Duration
}

// LimitsConfig bounds object/part sizes, upload lifetime and default quotas.
type LimitsConfig struct {
	ObjectMaxBytes            int64
	PartMaxBytes              int64
	UploadTTL                 time.Duration
	BucketDefaultQuotaBytes   int64
	BucketDefaultQuotaObjects int64
}

// GCConfig controls the background reaper.
type GCConfig struct {
	Interval time.Duration
	Grace    time.Duration
}

// FromEnv builds a Config from the environment. It returns non-fatal warnings for
// configurations that work but deserve operator attention.
func FromEnv() (*Config, []string, error) {
	var warnings []string
	hostname, _ := os.Hostname()
	c := &Config{
		ConnectionString: envString(EnvDSN, ""),
		ListenAddress:    envString(EnvAddr, envString(EnvFallbackHost, DefaultAddr)),
		BlobDir:          envString(EnvBlobDir, DefaultBlobDir),
		KeyDir:           envString(EnvKeyDir, DefaultKeyDir),
		LogLevel:         strings.ToLower(envString(EnvLogLevel, DefaultLogLevel)),
		NodeID:           envString(EnvNodeID, hostname),
		PublicBaseURL:    NormalizeBaseURL(envString(EnvPublicBaseURL, "")),
	}
	fallbackPort, err := envInt(EnvFallbackPort, DefaultPort)
	if err != nil {
		return nil, nil, err
	}
	port, err := envInt(EnvPort, fallbackPort)
	if err != nil {
		return nil, nil, err
	}
	c.ListenPort = port

	proxies, err := ParsePrefixes(envString(EnvTrustedProxies, ""))
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", EnvTrustedProxies, err)
	}
	c.TrustedProxies = proxies

	iamTimeout, err := envDuration(EnvTeamusersTimeout, DefaultIAMTimeout)
	if err != nil {
		return nil, nil, err
	}
	c.IAM = IAMConfig{
		BaseURL:      envString(EnvTeamusersBaseURL, ""),
		Issuer:       envString(EnvTeamusersIssuer, ""),
		Audience:     envString(EnvTeamusersAud, ""),
		ServiceToken: envString(EnvTeamusersToken, ""),
		ClientID:     envString(EnvTeamusersClient, ""),
		ClientSecret: envString(EnvTeamusersSecret, ""),
		NATSURL:      envString(EnvTeamusersNATS, ""),
		Timeout:      iamTimeout,
	}
	if c.IAM.ServiceToken != "" {
		warnings = append(warnings, EnvTeamusersToken+" is set: static service tokens do not rotate, prefer client credentials")
	}
	if c.IAM.Issuer == "" && c.IAM.BaseURL != "" {
		warnings = append(warnings, EnvTeamusersIssuer+" is not set: the teamusers default issuer \"teamusers\" is used")
	}

	if c.Presign.DefaultTTL, err = envDuration(EnvPresignDefaultTTL, DefaultPresignTTL); err != nil {
		return nil, nil, err
	}
	if c.Presign.MaxTTL, err = envDuration(EnvPresignMaxTTL, DefaultPresignMaxTTL); err != nil {
		return nil, nil, err
	}
	if c.Limits.ObjectMaxBytes, err = envInt64(EnvObjectMaxBytes, DefaultObjectMaxBytes); err != nil {
		return nil, nil, err
	}
	if c.Limits.PartMaxBytes, err = envInt64(EnvPartMaxBytes, DefaultPartMaxBytes); err != nil {
		return nil, nil, err
	}
	if c.Limits.UploadTTL, err = envDuration(EnvUploadTTL, DefaultUploadTTL); err != nil {
		return nil, nil, err
	}
	if c.Limits.BucketDefaultQuotaBytes, err = envInt64(EnvBucketQuotaBytes, DefaultBucketDefaultQuotaVal); err != nil {
		return nil, nil, err
	}
	if c.Limits.BucketDefaultQuotaObjects, err = envInt64(EnvBucketQuotaObjects, DefaultBucketDefaultQuotaVal); err != nil {
		return nil, nil, err
	}
	if c.GC.Interval, err = envDuration(EnvGCInterval, DefaultGCInterval); err != nil {
		return nil, nil, err
	}
	if c.GC.Grace, err = envDuration(EnvGCGrace, DefaultGCGrace); err != nil {
		return nil, nil, err
	}
	if c.IdempotencyTTL, err = envDuration(EnvIdempotencyTTL, DefaultIdempotencyTTL); err != nil {
		return nil, nil, err
	}
	return c, warnings, nil
}

// BindFlags registers every configuration flag on fs. Flags default to the current
// (environment derived) value, so parsing only overrides what the operator passed.
func BindFlags(fs *flag.FlagSet, c *Config) {
	fs.StringVar(&c.ConnectionString, "dsn", c.ConnectionString, "PostgreSQL connection string")
	fs.StringVar(&c.ListenAddress, "addr", c.ListenAddress, "listen address")
	fs.IntVar(&c.ListenPort, "port", c.ListenPort, "listen port (0 picks a free port)")
	fs.StringVar(&c.BlobDir, "blob-dir", c.BlobDir, "root directory holding blobs/, tmp/ and uploads/")
	fs.StringVar(&c.KeyDir, "key-dir", c.KeyDir, "directory holding local secret files")
	fs.StringVar(&c.LogLevel, "log-level", c.LogLevel, "log level: debug, info, warn or error")
	fs.StringVar(&c.NodeID, "node-id", c.NodeID, "node identifier reported in logs")
	fs.StringVar(&c.PublicBaseURL, "public-base-url", c.PublicBaseURL, "absolute origin for presigned links (empty derives it from the request)")

	fs.StringVar(&c.IAM.BaseURL, "teamusers-base-url", c.IAM.BaseURL, "teamusers IAM base URL")
	fs.StringVar(&c.IAM.Issuer, "teamusers-issuer", c.IAM.Issuer, "expected JWT issuer")
	fs.StringVar(&c.IAM.Audience, "teamusers-audience", c.IAM.Audience, "expected JWT audience")
	fs.StringVar(&c.IAM.ServiceToken, "teamusers-service-token", c.IAM.ServiceToken, "static teamusers service token")
	fs.StringVar(&c.IAM.ClientID, "teamusers-client-id", c.IAM.ClientID, "teamusers OAuth client id")
	fs.StringVar(&c.IAM.ClientSecret, "teamusers-client-secret", c.IAM.ClientSecret, "teamusers OAuth client secret")
	fs.StringVar(&c.IAM.NATSURL, "teamusers-nats-url", c.IAM.NATSURL, "teamusers NATS URL for revocation events")
	fs.DurationVar(&c.IAM.Timeout, "teamusers-timeout", c.IAM.Timeout, "teamusers HTTP timeout")

	fs.DurationVar(&c.Presign.DefaultTTL, "presign-default-ttl", c.Presign.DefaultTTL, "default presigned URL lifetime")
	fs.DurationVar(&c.Presign.MaxTTL, "presign-max-ttl", c.Presign.MaxTTL, "maximum presigned URL lifetime")

	fs.Int64Var(&c.Limits.ObjectMaxBytes, "object-max-bytes", c.Limits.ObjectMaxBytes, "maximum object size in bytes")
	fs.Int64Var(&c.Limits.PartMaxBytes, "part-max-bytes", c.Limits.PartMaxBytes, "maximum multipart part size in bytes")
	fs.DurationVar(&c.Limits.UploadTTL, "upload-ttl", c.Limits.UploadTTL, "multipart upload lifetime")
	fs.Int64Var(&c.Limits.BucketDefaultQuotaBytes, "bucket-default-quota-bytes", c.Limits.BucketDefaultQuotaBytes, "default bucket byte quota (0 = unlimited)")
	fs.Int64Var(&c.Limits.BucketDefaultQuotaObjects, "bucket-default-quota-objects", c.Limits.BucketDefaultQuotaObjects, "default bucket object quota (0 = unlimited)")

	fs.DurationVar(&c.GC.Interval, "gc-interval", c.GC.Interval, "garbage collection interval")
	fs.DurationVar(&c.GC.Grace, "gc-grace", c.GC.Grace, "grace period before an unreferenced blob is deleted")
	fs.DurationVar(&c.IdempotencyTTL, "idempotency-ttl", c.IdempotencyTTL, "idempotency record retention")

	fs.Func("trusted-proxies", "comma separated CIDRs trusted for X-Forwarded-For", func(v string) error {
		prefixes, err := ParsePrefixes(v)
		if err != nil {
			return err
		}
		c.TrustedProxies = prefixes
		return nil
	})
}

// Validate checks the configuration needed to serve traffic.
func (c *Config) Validate() error {
	var errs []error
	if strings.TrimSpace(c.ConnectionString) == "" {
		errs = append(errs, errors.New(EnvDSN+" (or -dsn) is required"))
	}
	if strings.TrimSpace(c.IAM.BaseURL) == "" {
		errs = append(errs, errors.New(EnvTeamusersBaseURL+" (or -teamusers-base-url) is required"))
	}
	if strings.TrimSpace(c.IAM.ServiceToken) == "" &&
		(strings.TrimSpace(c.IAM.ClientID) == "" || strings.TrimSpace(c.IAM.ClientSecret) == "") {
		errs = append(errs, errors.New("either a teamusers service token or a client id with client secret is required"))
	}
	if c.ListenPort < 0 || c.ListenPort > 65535 {
		errs = append(errs, fmt.Errorf("port %d out of range 0..65535", c.ListenPort))
	}
	if !validLogLevel(c.LogLevel) {
		errs = append(errs, fmt.Errorf("invalid log level %q", c.LogLevel))
	}
	if c.PublicBaseURL != "" {
		normalized := NormalizeBaseURL(c.PublicBaseURL)
		parsed, err := url.Parse(normalized)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("public base url %q is not a valid URL", c.PublicBaseURL))
		case parsed.Scheme != "http" && parsed.Scheme != "https":
			errs = append(errs, fmt.Errorf("public base url %q must use http or https", c.PublicBaseURL))
		case parsed.Host == "":
			errs = append(errs, fmt.Errorf("public base url %q must be absolute", c.PublicBaseURL))
		case parsed.RawQuery != "" || parsed.Fragment != "":
			errs = append(errs, fmt.Errorf("public base url %q must not carry a query or fragment", c.PublicBaseURL))
		default:
			c.PublicBaseURL = normalized
		}
	}
	if c.IAM.Timeout <= 0 {
		errs = append(errs, errors.New("teamusers timeout must be positive"))
	}
	if c.Presign.DefaultTTL <= 0 {
		errs = append(errs, errors.New("presign default ttl must be positive"))
	}
	if c.Presign.MaxTTL <= 0 {
		errs = append(errs, errors.New("presign max ttl must be positive"))
	}
	if c.Presign.DefaultTTL > c.Presign.MaxTTL {
		errs = append(errs, fmt.Errorf("presign default ttl %s exceeds max ttl %s", c.Presign.DefaultTTL, c.Presign.MaxTTL))
	}
	if c.Limits.ObjectMaxBytes <= 0 {
		errs = append(errs, errors.New("object max bytes must be positive"))
	}
	if c.Limits.PartMaxBytes <= 0 {
		errs = append(errs, errors.New("part max bytes must be positive"))
	}
	if c.Limits.UploadTTL <= 0 {
		errs = append(errs, errors.New("upload ttl must be positive"))
	}
	if c.Limits.BucketDefaultQuotaBytes < 0 {
		errs = append(errs, errors.New("bucket default quota bytes must not be negative"))
	}
	if c.Limits.BucketDefaultQuotaObjects < 0 {
		errs = append(errs, errors.New("bucket default quota objects must not be negative"))
	}
	if c.GC.Interval <= 0 {
		errs = append(errs, errors.New("gc interval must be positive"))
	}
	if c.GC.Grace < 0 {
		errs = append(errs, errors.New("gc grace must not be negative"))
	}
	if c.IdempotencyTTL <= 0 {
		errs = append(errs, errors.New("idempotency ttl must be positive"))
	}
	if strings.TrimSpace(c.BlobDir) == "" {
		errs = append(errs, errors.New("blob dir is required"))
	}
	if strings.TrimSpace(c.KeyDir) == "" {
		errs = append(errs, errors.New("key dir is required"))
	}
	return errors.Join(errs...)
}

// Redacted renders the effective configuration as sorted KEY=value lines with
// every secret masked. It is safe to print.
func (c *Config) Redacted() []string {
	proxies := make([]string, 0, len(c.TrustedProxies))
	for _, p := range c.TrustedProxies {
		proxies = append(proxies, p.String())
	}
	return []string{
		EnvDSN + "=" + RedactDSN(c.ConnectionString),
		EnvAddr + "=" + c.ListenAddress,
		EnvPort + "=" + strconv.Itoa(c.ListenPort),
		EnvBlobDir + "=" + c.BlobDir,
		EnvKeyDir + "=" + c.KeyDir,
		EnvLogLevel + "=" + c.LogLevel,
		EnvNodeID + "=" + c.NodeID,
		EnvPublicBaseURL + "=" + NormalizeBaseURL(c.PublicBaseURL),
		EnvTrustedProxies + "=" + strings.Join(proxies, ","),
		EnvTeamusersBaseURL + "=" + c.IAM.BaseURL,
		EnvTeamusersIssuer + "=" + c.IAM.Issuer,
		EnvTeamusersAud + "=" + c.IAM.Audience,
		EnvTeamusersToken + "=" + maskSecret(c.IAM.ServiceToken),
		EnvTeamusersClient + "=" + c.IAM.ClientID,
		EnvTeamusersSecret + "=" + maskSecret(c.IAM.ClientSecret),
		EnvTeamusersNATS + "=" + c.IAM.NATSURL,
		EnvTeamusersTimeout + "=" + c.IAM.Timeout.String(),
		EnvPresignDefaultTTL + "=" + c.Presign.DefaultTTL.String(),
		EnvPresignMaxTTL + "=" + c.Presign.MaxTTL.String(),
		EnvObjectMaxBytes + "=" + strconv.FormatInt(c.Limits.ObjectMaxBytes, 10),
		EnvPartMaxBytes + "=" + strconv.FormatInt(c.Limits.PartMaxBytes, 10),
		EnvUploadTTL + "=" + c.Limits.UploadTTL.String(),
		EnvBucketQuotaBytes + "=" + strconv.FormatInt(c.Limits.BucketDefaultQuotaBytes, 10),
		EnvBucketQuotaObjects + "=" + strconv.FormatInt(c.Limits.BucketDefaultQuotaObjects, 10),
		EnvGCInterval + "=" + c.GC.Interval.String(),
		EnvGCGrace + "=" + c.GC.Grace.String(),
		EnvIdempotencyTTL + "=" + c.IdempotencyTTL.String(),
	}
}

// LogLevelValue returns the parsed slog level.
func (c *Config) LogLevelValue() (slog.Level, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(strings.ToUpper(c.LogLevel))); err != nil {
		return 0, fmt.Errorf("invalid log level %q", c.LogLevel)
	}
	return level, nil
}

// ParsePrefixes parses a comma separated list of CIDRs or bare IP addresses.
func ParsePrefixes(raw string) ([]netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(part); err == nil {
			out = append(out, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR or IP %q", part)
		}
		addr = addr.Unmap()
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, nil
}

// NormalizeBaseURL trims surrounding spaces and trailing slashes from a
// configured public base URL so it can be joined with a path verbatim.
func NormalizeBaseURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

// RedactDSN masks the password of a PostgreSQL connection string in either URL or
// keyword/value form.
func RedactDSN(dsn string) string {
	if dsn == "" {
		return ""
	}
	if strings.Contains(dsn, "://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "***"
		}
		if _, hasPassword := u.User.Password(); hasPassword {
			u.User = url.UserPassword(u.User.Username(), "***")
			// url.URL escapes the mask; render it verbatim.
			return strings.ReplaceAll(u.String(), "%2A%2A%2A", "***")
		}
		return u.String()
	}
	fields := strings.Fields(dsn)
	for i, field := range fields {
		if strings.HasPrefix(strings.ToLower(field), "password=") {
			fields[i] = "password=***"
		}
	}
	return strings.Join(fields, " ")
}

func validLogLevel(level string) bool {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug", "info", "warn", "error":
		return true
	default:
		return false
	}
}

func maskSecret(value string) string {
	if value == "" {
		return ""
	}
	return "***"
}

func envString(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func envInt(key string, fallback int) (int, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: invalid integer %q", key, raw)
	}
	return value, nil
}

func envInt64(key string, fallback int64) (int64, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid integer %q", key, raw)
	}
	return value, nil
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	raw, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("%s: invalid duration %q", key, raw)
	}
	return value, nil
}
