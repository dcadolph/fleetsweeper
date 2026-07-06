// Package geo locates clusters on Earth from their node region/zone labels.
// Coordinates here are the approximate centroid of each cloud provider's
// public region. They are intentionally approximate — exact data-center
// coordinates are not always published, and what matters for a fleet globe
// is "this cluster is in Frankfurt, not Tokyo", not GPS-level accuracy.
package geo

// Coord is the approximate centroid (latitude, longitude) of a region.
type Coord struct {
	// Lat is degrees north (positive) or south (negative).
	Lat float64
	// Lng is degrees east (positive) or west (negative).
	Lng float64
	// Provider is the cloud provider this region belongs to.
	Provider string
	// City is a human-readable label for the region centroid.
	City string
}

// regionTable maps cloud-provider region identifiers to approximate
// coordinates. Keys are the exact strings clouds emit on node labels
// (topology.kubernetes.io/region). Entries are organized by provider for
// readability; lookup is a single map read.
var regionTable = map[string]Coord{
	// AWS
	"us-east-1":      {Lat: 38.95, Lng: -77.46, Provider: "AWS", City: "N. Virginia"},
	"us-east-2":      {Lat: 39.96, Lng: -83.00, Provider: "AWS", City: "Ohio"},
	"us-west-1":      {Lat: 37.77, Lng: -122.42, Provider: "AWS", City: "N. California"},
	"us-west-2":      {Lat: 45.51, Lng: -122.68, Provider: "AWS", City: "Oregon"},
	"ca-central-1":   {Lat: 45.50, Lng: -73.57, Provider: "AWS", City: "Canada Central"},
	"ca-west-1":      {Lat: 51.05, Lng: -114.07, Provider: "AWS", City: "Calgary"},
	"sa-east-1":      {Lat: -23.55, Lng: -46.63, Provider: "AWS", City: "São Paulo"},
	"eu-west-1":      {Lat: 53.33, Lng: -6.25, Provider: "AWS", City: "Ireland"},
	"eu-west-2":      {Lat: 51.50, Lng: -0.13, Provider: "AWS", City: "London"},
	"eu-west-3":      {Lat: 48.86, Lng: 2.35, Provider: "AWS", City: "Paris"},
	"eu-central-1":   {Lat: 50.11, Lng: 8.68, Provider: "AWS", City: "Frankfurt"},
	"eu-central-2":   {Lat: 47.37, Lng: 8.55, Provider: "AWS", City: "Zurich"},
	"eu-north-1":     {Lat: 59.33, Lng: 18.07, Provider: "AWS", City: "Stockholm"},
	"eu-south-1":     {Lat: 45.46, Lng: 9.19, Provider: "AWS", City: "Milan"},
	"eu-south-2":     {Lat: 40.42, Lng: -3.70, Provider: "AWS", City: "Spain"},
	"af-south-1":     {Lat: -33.92, Lng: 18.42, Provider: "AWS", City: "Cape Town"},
	"me-south-1":     {Lat: 26.07, Lng: 50.55, Provider: "AWS", City: "Bahrain"},
	"me-central-1":   {Lat: 25.27, Lng: 55.30, Provider: "AWS", City: "UAE"},
	"il-central-1":   {Lat: 32.08, Lng: 34.78, Provider: "AWS", City: "Tel Aviv"},
	"ap-east-1":      {Lat: 22.30, Lng: 114.17, Provider: "AWS", City: "Hong Kong"},
	"ap-south-1":     {Lat: 19.08, Lng: 72.88, Provider: "AWS", City: "Mumbai"},
	"ap-south-2":     {Lat: 17.39, Lng: 78.49, Provider: "AWS", City: "Hyderabad"},
	"ap-southeast-1": {Lat: 1.35, Lng: 103.82, Provider: "AWS", City: "Singapore"},
	"ap-southeast-2": {Lat: -33.87, Lng: 151.21, Provider: "AWS", City: "Sydney"},
	"ap-southeast-3": {Lat: -6.21, Lng: 106.85, Provider: "AWS", City: "Jakarta"},
	"ap-southeast-4": {Lat: -37.81, Lng: 144.96, Provider: "AWS", City: "Melbourne"},
	"ap-northeast-1": {Lat: 35.68, Lng: 139.69, Provider: "AWS", City: "Tokyo"},
	"ap-northeast-2": {Lat: 37.57, Lng: 126.98, Provider: "AWS", City: "Seoul"},
	"ap-northeast-3": {Lat: 34.69, Lng: 135.50, Provider: "AWS", City: "Osaka"},
	"cn-north-1":     {Lat: 39.90, Lng: 116.41, Provider: "AWS China", City: "Beijing"},
	"cn-northwest-1": {Lat: 38.49, Lng: 106.23, Provider: "AWS China", City: "Ningxia"},

	// GCP
	"us-central1":             {Lat: 41.26, Lng: -95.93, Provider: "GCP", City: "Iowa"},
	"us-east1":                {Lat: 33.20, Lng: -80.00, Provider: "GCP", City: "S. Carolina"},
	"us-east4":                {Lat: 39.04, Lng: -77.49, Provider: "GCP", City: "N. Virginia"},
	"us-east5":                {Lat: 39.96, Lng: -83.00, Provider: "GCP", City: "Columbus"},
	"us-south1":               {Lat: 32.78, Lng: -96.80, Provider: "GCP", City: "Dallas"},
	"us-west1":                {Lat: 45.60, Lng: -121.18, Provider: "GCP", City: "Oregon"},
	"us-west2":                {Lat: 34.05, Lng: -118.24, Provider: "GCP", City: "Los Angeles"},
	"us-west3":                {Lat: 40.76, Lng: -111.89, Provider: "GCP", City: "Salt Lake City"},
	"us-west4":                {Lat: 36.17, Lng: -115.14, Provider: "GCP", City: "Las Vegas"},
	"northamerica-northeast1": {Lat: 45.50, Lng: -73.57, Provider: "GCP", City: "Montréal"},
	"northamerica-northeast2": {Lat: 43.65, Lng: -79.38, Provider: "GCP", City: "Toronto"},
	"southamerica-east1":      {Lat: -23.55, Lng: -46.63, Provider: "GCP", City: "São Paulo"},
	"southamerica-west1":      {Lat: -33.45, Lng: -70.67, Provider: "GCP", City: "Santiago"},
	"europe-west1":            {Lat: 50.85, Lng: 4.35, Provider: "GCP", City: "Belgium"},
	"europe-west2":            {Lat: 51.50, Lng: -0.13, Provider: "GCP", City: "London"},
	"europe-west3":            {Lat: 50.11, Lng: 8.68, Provider: "GCP", City: "Frankfurt"},
	"europe-west4":            {Lat: 53.43, Lng: 6.79, Provider: "GCP", City: "Netherlands"},
	"europe-west6":            {Lat: 47.37, Lng: 8.55, Provider: "GCP", City: "Zurich"},
	"europe-west8":            {Lat: 45.46, Lng: 9.19, Provider: "GCP", City: "Milan"},
	"europe-west9":            {Lat: 48.86, Lng: 2.35, Provider: "GCP", City: "Paris"},
	"europe-west10":           {Lat: 52.52, Lng: 13.41, Provider: "GCP", City: "Berlin"},
	"europe-west12":           {Lat: 45.07, Lng: 7.69, Provider: "GCP", City: "Turin"},
	"europe-north1":           {Lat: 60.57, Lng: 27.18, Provider: "GCP", City: "Finland"},
	"europe-central2":         {Lat: 52.23, Lng: 21.01, Provider: "GCP", City: "Warsaw"},
	"europe-southwest1":       {Lat: 40.42, Lng: -3.70, Provider: "GCP", City: "Madrid"},
	"asia-east1":              {Lat: 24.05, Lng: 120.51, Provider: "GCP", City: "Taiwan"},
	"asia-east2":              {Lat: 22.30, Lng: 114.17, Provider: "GCP", City: "Hong Kong"},
	"asia-northeast1":         {Lat: 35.68, Lng: 139.69, Provider: "GCP", City: "Tokyo"},
	"asia-northeast2":         {Lat: 34.69, Lng: 135.50, Provider: "GCP", City: "Osaka"},
	"asia-northeast3":         {Lat: 37.57, Lng: 126.98, Provider: "GCP", City: "Seoul"},
	"asia-south1":             {Lat: 19.08, Lng: 72.88, Provider: "GCP", City: "Mumbai"},
	"asia-south2":             {Lat: 28.61, Lng: 77.21, Provider: "GCP", City: "Delhi"},
	"asia-southeast1":         {Lat: 1.35, Lng: 103.82, Provider: "GCP", City: "Singapore"},
	"asia-southeast2":         {Lat: -6.21, Lng: 106.85, Provider: "GCP", City: "Jakarta"},
	"australia-southeast1":    {Lat: -33.87, Lng: 151.21, Provider: "GCP", City: "Sydney"},
	"australia-southeast2":    {Lat: -37.81, Lng: 144.96, Provider: "GCP", City: "Melbourne"},
	"me-west1":                {Lat: 32.08, Lng: 34.78, Provider: "GCP", City: "Tel Aviv"},
	"me-central1":             {Lat: 24.47, Lng: 54.37, Provider: "GCP", City: "Doha"},
	"africa-south1":           {Lat: -26.20, Lng: 28.05, Provider: "GCP", City: "Johannesburg"},

	// Azure
	"eastus":             {Lat: 37.43, Lng: -78.66, Provider: "Azure", City: "Virginia"},
	"eastus2":            {Lat: 36.69, Lng: -78.45, Provider: "Azure", City: "Virginia"},
	"eastus3":            {Lat: 32.81, Lng: -96.80, Provider: "Azure", City: "Dallas"},
	"westus":             {Lat: 37.77, Lng: -122.42, Provider: "Azure", City: "California"},
	"westus2":            {Lat: 47.25, Lng: -119.85, Provider: "Azure", City: "Washington"},
	"westus3":            {Lat: 33.45, Lng: -112.07, Provider: "Azure", City: "Arizona"},
	"centralus":          {Lat: 41.59, Lng: -93.62, Provider: "Azure", City: "Iowa"},
	"northcentralus":     {Lat: 41.88, Lng: -87.63, Provider: "Azure", City: "Illinois"},
	"southcentralus":     {Lat: 29.42, Lng: -98.50, Provider: "Azure", City: "Texas"},
	"westcentralus":      {Lat: 41.14, Lng: -104.82, Provider: "Azure", City: "Wyoming"},
	"canadacentral":      {Lat: 43.65, Lng: -79.38, Provider: "Azure", City: "Toronto"},
	"canadaeast":         {Lat: 46.81, Lng: -71.21, Provider: "Azure", City: "Quebec"},
	"brazilsouth":        {Lat: -23.55, Lng: -46.63, Provider: "Azure", City: "São Paulo"},
	"brazilsoutheast":    {Lat: -22.91, Lng: -43.20, Provider: "Azure", City: "Rio de Janeiro"},
	"northeurope":        {Lat: 53.33, Lng: -6.25, Provider: "Azure", City: "Ireland"},
	"westeurope":         {Lat: 52.37, Lng: 4.90, Provider: "Azure", City: "Netherlands"},
	"uksouth":            {Lat: 51.50, Lng: -0.13, Provider: "Azure", City: "London"},
	"ukwest":             {Lat: 53.43, Lng: -3.08, Provider: "Azure", City: "Cardiff"},
	"francecentral":      {Lat: 48.86, Lng: 2.35, Provider: "Azure", City: "Paris"},
	"francesouth":        {Lat: 43.30, Lng: 5.37, Provider: "Azure", City: "Marseille"},
	"germanywestcentral": {Lat: 50.11, Lng: 8.68, Provider: "Azure", City: "Frankfurt"},
	"germanynorth":       {Lat: 53.55, Lng: 9.99, Provider: "Azure", City: "Berlin"},
	"norwayeast":         {Lat: 59.91, Lng: 10.75, Provider: "Azure", City: "Oslo"},
	"norwaywest":         {Lat: 58.97, Lng: 5.73, Provider: "Azure", City: "Stavanger"},
	"swedencentral":      {Lat: 60.67, Lng: 17.14, Provider: "Azure", City: "Gävle"},
	"switzerlandnorth":   {Lat: 47.37, Lng: 8.55, Provider: "Azure", City: "Zurich"},
	"switzerlandwest":    {Lat: 46.20, Lng: 6.14, Provider: "Azure", City: "Geneva"},
	"polandcentral":      {Lat: 52.23, Lng: 21.01, Provider: "Azure", City: "Warsaw"},
	"italynorth":         {Lat: 45.46, Lng: 9.19, Provider: "Azure", City: "Milan"},
	"spaincentral":       {Lat: 40.42, Lng: -3.70, Provider: "Azure", City: "Madrid"},
	"southafricanorth":   {Lat: -26.20, Lng: 28.05, Provider: "Azure", City: "Johannesburg"},
	"southafricawest":    {Lat: -33.92, Lng: 18.42, Provider: "Azure", City: "Cape Town"},
	"uaenorth":           {Lat: 25.27, Lng: 55.30, Provider: "Azure", City: "Dubai"},
	"uaecentral":         {Lat: 24.47, Lng: 54.37, Provider: "Azure", City: "Abu Dhabi"},
	"qatarcentral":       {Lat: 25.29, Lng: 51.53, Provider: "Azure", City: "Doha"},
	"israelcentral":      {Lat: 32.08, Lng: 34.78, Provider: "Azure", City: "Tel Aviv"},
	"australiaeast":      {Lat: -33.87, Lng: 151.21, Provider: "Azure", City: "Sydney"},
	"australiasoutheast": {Lat: -37.81, Lng: 144.96, Provider: "Azure", City: "Melbourne"},
	"australiacentral":   {Lat: -35.28, Lng: 149.13, Provider: "Azure", City: "Canberra"},
	"australiacentral2":  {Lat: -35.28, Lng: 149.13, Provider: "Azure", City: "Canberra"},
	"southeastasia":      {Lat: 1.35, Lng: 103.82, Provider: "Azure", City: "Singapore"},
	"eastasia":           {Lat: 22.30, Lng: 114.17, Provider: "Azure", City: "Hong Kong"},
	"japaneast":          {Lat: 35.68, Lng: 139.69, Provider: "Azure", City: "Tokyo"},
	"japanwest":          {Lat: 34.69, Lng: 135.50, Provider: "Azure", City: "Osaka"},
	"koreacentral":       {Lat: 37.57, Lng: 126.98, Provider: "Azure", City: "Seoul"},
	"koreasouth":         {Lat: 35.18, Lng: 129.08, Provider: "Azure", City: "Busan"},
	"indiacentral":       {Lat: 18.52, Lng: 73.86, Provider: "Azure", City: "Pune"},
	"indiasouth":         {Lat: 12.97, Lng: 80.21, Provider: "Azure", City: "Chennai"},
	"indiawest":          {Lat: 19.08, Lng: 72.88, Provider: "Azure", City: "Mumbai"},
	"jioindiacentral":    {Lat: 21.17, Lng: 72.83, Provider: "Azure", City: "Nagpur"},
	"jioindiawest":       {Lat: 21.17, Lng: 72.83, Provider: "Azure", City: "Jamnagar"},
	"chinaeast":          {Lat: 31.23, Lng: 121.47, Provider: "Azure China", City: "Shanghai"},
	"chinaeast2":         {Lat: 31.23, Lng: 121.47, Provider: "Azure China", City: "Shanghai"},
	"chinanorth":         {Lat: 39.90, Lng: 116.41, Provider: "Azure China", City: "Beijing"},
	"chinanorth2":        {Lat: 39.90, Lng: 116.41, Provider: "Azure China", City: "Beijing"},

	// DigitalOcean
	"nyc1": {Lat: 40.71, Lng: -74.00, Provider: "DigitalOcean", City: "New York"},
	"nyc2": {Lat: 40.71, Lng: -74.00, Provider: "DigitalOcean", City: "New York"},
	"nyc3": {Lat: 40.71, Lng: -74.00, Provider: "DigitalOcean", City: "New York"},
	"sfo1": {Lat: 37.77, Lng: -122.42, Provider: "DigitalOcean", City: "San Francisco"},
	"sfo2": {Lat: 37.77, Lng: -122.42, Provider: "DigitalOcean", City: "San Francisco"},
	"sfo3": {Lat: 37.77, Lng: -122.42, Provider: "DigitalOcean", City: "San Francisco"},
	"ams2": {Lat: 52.37, Lng: 4.90, Provider: "DigitalOcean", City: "Amsterdam"},
	"ams3": {Lat: 52.37, Lng: 4.90, Provider: "DigitalOcean", City: "Amsterdam"},
	"sgp1": {Lat: 1.35, Lng: 103.82, Provider: "DigitalOcean", City: "Singapore"},
	"lon1": {Lat: 51.50, Lng: -0.13, Provider: "DigitalOcean", City: "London"},
	"fra1": {Lat: 50.11, Lng: 8.68, Provider: "DigitalOcean", City: "Frankfurt"},
	"tor1": {Lat: 43.65, Lng: -79.38, Provider: "DigitalOcean", City: "Toronto"},
	"blr1": {Lat: 12.97, Lng: 77.59, Provider: "DigitalOcean", City: "Bangalore"},
	"syd1": {Lat: -33.87, Lng: 151.21, Provider: "DigitalOcean", City: "Sydney"},

	// Oracle Cloud
	"us-ashburn-1":      {Lat: 39.04, Lng: -77.49, Provider: "OCI", City: "Ashburn"},
	"us-phoenix-1":      {Lat: 33.45, Lng: -112.07, Provider: "OCI", City: "Phoenix"},
	"us-sanjose-1":      {Lat: 37.34, Lng: -121.89, Provider: "OCI", City: "San Jose"},
	"us-chicago-1":      {Lat: 41.88, Lng: -87.63, Provider: "OCI", City: "Chicago"},
	"ca-toronto-1":      {Lat: 43.65, Lng: -79.38, Provider: "OCI", City: "Toronto"},
	"ca-montreal-1":     {Lat: 45.50, Lng: -73.57, Provider: "OCI", City: "Montréal"},
	"eu-frankfurt-1":    {Lat: 50.11, Lng: 8.68, Provider: "OCI", City: "Frankfurt"},
	"eu-amsterdam-1":    {Lat: 52.37, Lng: 4.90, Provider: "OCI", City: "Amsterdam"},
	"eu-zurich-1":       {Lat: 47.37, Lng: 8.55, Provider: "OCI", City: "Zurich"},
	"eu-madrid-1":       {Lat: 40.42, Lng: -3.70, Provider: "OCI", City: "Madrid"},
	"uk-london-1":       {Lat: 51.50, Lng: -0.13, Provider: "OCI", City: "London"},
	"sa-saopaulo-1":     {Lat: -23.55, Lng: -46.63, Provider: "OCI", City: "São Paulo"},
	"sa-vinhedo-1":      {Lat: -23.03, Lng: -46.97, Provider: "OCI", City: "Vinhedo"},
	"sa-santiago-1":     {Lat: -33.45, Lng: -70.67, Provider: "OCI", City: "Santiago"},
	"sa-bogota-1":       {Lat: 4.71, Lng: -74.07, Provider: "OCI", City: "Bogotá"},
	"ap-mumbai-1":       {Lat: 19.08, Lng: 72.88, Provider: "OCI", City: "Mumbai"},
	"ap-hyderabad-1":    {Lat: 17.39, Lng: 78.49, Provider: "OCI", City: "Hyderabad"},
	"ap-singapore-1":    {Lat: 1.35, Lng: 103.82, Provider: "OCI", City: "Singapore"},
	"ap-tokyo-1":        {Lat: 35.68, Lng: 139.69, Provider: "OCI", City: "Tokyo"},
	"ap-osaka-1":        {Lat: 34.69, Lng: 135.50, Provider: "OCI", City: "Osaka"},
	"ap-seoul-1":        {Lat: 37.57, Lng: 126.98, Provider: "OCI", City: "Seoul"},
	"ap-chuncheon-1":    {Lat: 37.87, Lng: 127.73, Provider: "OCI", City: "Chuncheon"},
	"ap-sydney-1":       {Lat: -33.87, Lng: 151.21, Provider: "OCI", City: "Sydney"},
	"ap-melbourne-1":    {Lat: -37.81, Lng: 144.96, Provider: "OCI", City: "Melbourne"},
	"me-dubai-1":        {Lat: 25.27, Lng: 55.30, Provider: "OCI", City: "Dubai"},
	"me-jeddah-1":       {Lat: 21.49, Lng: 39.19, Provider: "OCI", City: "Jeddah"},
	"af-johannesburg-1": {Lat: -26.20, Lng: 28.05, Provider: "OCI", City: "Johannesburg"},

	// Alibaba Cloud (common ones)
	"cn-hangzhou":    {Lat: 30.27, Lng: 120.15, Provider: "Alibaba", City: "Hangzhou"},
	"cn-shanghai":    {Lat: 31.23, Lng: 121.47, Provider: "Alibaba", City: "Shanghai"},
	"cn-beijing":     {Lat: 39.90, Lng: 116.41, Provider: "Alibaba", City: "Beijing"},
	"cn-shenzhen":    {Lat: 22.54, Lng: 114.05, Provider: "Alibaba", City: "Shenzhen"},
	"cn-hongkong":    {Lat: 22.30, Lng: 114.17, Provider: "Alibaba", City: "Hong Kong"},
	"ap-southeast-5": {Lat: -6.21, Lng: 106.85, Provider: "Alibaba", City: "Jakarta"},
	"ap-southeast-6": {Lat: 14.60, Lng: 120.98, Provider: "Alibaba", City: "Manila"},

	// IBM Cloud
	"us-south": {Lat: 32.78, Lng: -96.80, Provider: "IBM", City: "Dallas"},
	"us-east":  {Lat: 38.95, Lng: -77.46, Provider: "IBM", City: "Washington DC"},
	"br-sao":   {Lat: -23.55, Lng: -46.63, Provider: "IBM", City: "São Paulo"},
	"eu-de":    {Lat: 50.11, Lng: 8.68, Provider: "IBM", City: "Frankfurt"},
	"eu-gb":    {Lat: 51.50, Lng: -0.13, Provider: "IBM", City: "London"},
	"eu-es":    {Lat: 40.42, Lng: -3.70, Provider: "IBM", City: "Madrid"},
	"jp-tok":   {Lat: 35.68, Lng: 139.69, Provider: "IBM", City: "Tokyo"},
	"jp-osa":   {Lat: 34.69, Lng: 135.50, Provider: "IBM", City: "Osaka"},
	"au-syd":   {Lat: -33.87, Lng: 151.21, Provider: "IBM", City: "Sydney"},
	"ca-tor":   {Lat: 43.65, Lng: -79.38, Provider: "IBM", City: "Toronto"},
}

// Lookup returns the coordinate for a region name, or ok=false when the
// region is not in the table. Callers should fall back to zone parsing
// (a zone like "us-east-1a" trims to a known region).
func Lookup(region string) (Coord, bool) {
	c, ok := regionTable[region]
	return c, ok
}

// LookupZone strips a trailing single-letter zone suffix and looks up the
// resulting region. AWS zones look like "us-east-1a"; GCP zones look like
// "us-central1-b". Both shapes are handled.
func LookupZone(zone string) (Coord, bool) {
	if c, ok := regionTable[zone]; ok {
		return c, true
	}
	if len(zone) > 1 {
		last := zone[len(zone)-1]
		if last >= 'a' && last <= 'z' {
			trimmed := zone[:len(zone)-1]
			if c, ok := regionTable[trimmed]; ok {
				return c, true
			}
			if len(trimmed) > 0 && trimmed[len(trimmed)-1] == '-' {
				trimmed = trimmed[:len(trimmed)-1]
				if c, ok := regionTable[trimmed]; ok {
					return c, true
				}
			}
		}
	}
	return Coord{}, false
}
