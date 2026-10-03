package iamauth

// CatalogEntry is one permission key this service owns together with the
// human-readable description registered in teamusers.
type CatalogEntry struct {
	Key         string
	Description string
}

// Catalog lists every permission key nsc-filehouse registers with
// teamusers. Keys are ordered least-privilege first within each action so the
// list reads as documentation: own, team, any.
//
// The list matches the authorization model of the frozen service contract,
// where delete and share use the same three scopes as read and write.
var Catalog = []CatalogEntry{
	{Key: "filehouse:read:own", Description: "Read objects and list buckets the subject owns"},
	{Key: "filehouse:read:team", Description: "Read objects and list buckets owned by the subject's team"},
	{Key: "filehouse:read:any", Description: "Read any object or bucket on the platform"},
	{Key: "filehouse:write:own", Description: "Upload objects, create personal buckets, and manage multipart uploads in buckets the subject owns"},
	{Key: "filehouse:write:team", Description: "Upload objects and manage multipart uploads in buckets owned by the subject's team"},
	{Key: "filehouse:write:any", Description: "Upload objects and manage multipart uploads in any bucket"},
	{Key: "filehouse:delete:own", Description: "Delete objects and empty buckets the subject owns"},
	{Key: "filehouse:delete:team", Description: "Delete objects and empty buckets owned by the subject's team"},
	{Key: "filehouse:delete:any", Description: "Delete any object or empty bucket on the platform"},
	{Key: "filehouse:share:own", Description: "Mint presigned URLs for objects in buckets the subject owns"},
	{Key: "filehouse:share:team", Description: "Mint presigned URLs for objects in buckets owned by the subject's team"},
	{Key: "filehouse:share:any", Description: "Mint presigned URLs for any object on the platform"},
	{Key: "filehouse:manage:any", Description: "Administer quotas, platform statistics, and garbage collection"},
}

// Keys returns a copy of the catalog keys in catalog order. Registration and
// the generated documentation both use this list, so neither can drift from
// the other.
func Keys() []string {
	keys := make([]string, 0, len(Catalog))
	for _, entry := range Catalog {
		keys = append(keys, entry.Key)
	}
	return keys
}
