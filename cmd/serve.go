

package main
import (
	"fmt"
	"github.com/gomodule/redigo/redis"
	"log"
	"os"
	"os/signal"
	"github.com/spf13/cobra"
	"syscall"
	"encoding/json"
	"strings"
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"database/sql"
	"bufio"
	_ "github.com/go-sql-driver/mysql"
	"time"
	"github.com/veqryn/go-email/email"
	"archive/zip"
	"github.com/likexian/whois-go"
	"net"
)


var (
	configPath string
	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "start the small SMTP server",
		Run:   serve,
	}



	signalChannel = make(chan os.Signal, 1) // for trapping SIGHUP and friends
)


//MessageQueueItem struct to match what goes in from smtp handler
type MessageQueueItem struct {
	Hash			string `json:"Hash"`
	ClientID		string `json:"ClientID"`
	MessageData		string `json:"MessageData"`
}

//DmarcReport def
type DmarcReport struct {
	XMLName		xml.Name		`xml:"feedback"`
	Metadata	*DmarcMeta		`xml:"report_metadata"`
	Policy 		*DmarcPolicy	`xml:"policy_published"`
	Record		[]DmarcRecord	`xml:"record"`
}

//DmarcMeta def
type DmarcMeta struct {
	XMLName		xml.Name		`xml:"report_metadata"`
	OrgName		string			`xml:"org_name"`
	Email		string			`xml:"email"`
	ReportID	string			`xml:"report_id"`
	DateRange	*DmarcDateRange	`xml:"date_range"`
}

//DmarcDateRange def
type DmarcDateRange struct {
	Begin	string	`xml:"begin"`
	End		string	`xml:"end"`
}

//DmarcPolicy def
type DmarcPolicy struct {
	Domain	string	`xml:"domain"`
	Dkim	string	`xml:"adkim"`
	Spf		string	`xml:"aspf"`
	P		string	`xml:"p"`
	Percent	string	`xml:"pct"`
}

//DmarcRecord def
type DmarcRecord struct {
	XMLName		xml.Name				`xml:"record"`
	Row			DmarcRecordRow			`xml:"row"`
	Identifiers	*DmarcRecordIdentifiers	`xml:"identifiers"`
	AuthResults	*DmarcRecordAuthResults	`xml:"auth_results"`
}

//DmarcRecordRow def
type DmarcRecordRow struct {
	SourceIP			string					`xml:"source_ip"`
	Count				int					`xml:"count"`
	PolicyEvaluated		*DmarcRecordRowPolEval	`xml:"policy_evaluated"`
		
}

//DmarcRecordRowPolEval def
type DmarcRecordRowPolEval struct {
	Disposition			string	`xml:"disposition"`
	Dkim				string	`xml:"dkim"`
	Spf					string	`xml:"spf"`
}

//DmarcRecordIdentifiers def
type DmarcRecordIdentifiers struct {
	HeaderFrom	string	`xml:"header_from"`
}

//DmarcRecordAuthResults def
type DmarcRecordAuthResults struct {
	Dkim	[]DmarcRecordDkimAuthResult	`xml:"dkim"`
	Spf		*DmarcRecordSpfAuthResult	`xml:"spf"`
}

//DmarcRecordAuthResult def
type DmarcRecordDkimAuthResult struct {
	XMLName	xml.Name	`xml:"dkim"`
	Domain	string		`xml:"domain"`
	Result	string		`xml:"result"`
}

//DmarcRecordAuthResult def
type DmarcRecordSpfAuthResult struct {
	XMLName	xml.Name	`xml:"spf"`
	Domain	string		`xml:"domain"`
	Result	string		`xml:"result"`
}

//FlatDmarcRecord def
type FlatDmarcRecord struct {
	Id				int
	ProcessedTime	time.Time
	MsgHash			string
	ClientID		string
	OrgName			string
	DmarcDomain		string
	SourceIP		string
	SourceCount		int
	Disposition		string
	DmarcSPF		string
	DmarcDkim		string
	HeaderFrom		string
	DkimDomain		string
	DkimResult		string
	SpfDomain		string
	SpfResult		string
	Provider		string
	Hostname		string
}

func dbConn() (db *sql.DB) {
    dbDriver := "mysql"
	sqlDsn := os.Getenv("DBUSER") + ":" + os.Getenv("DBPASS") + "@tcp(" + os.Getenv("DBHOST") + ":" + os.Getenv("DBPORT") + ")/" + os.Getenv("DBNAME") + "?readTimeout=10s&writeTimeout=10s"
    db, err := sql.Open(dbDriver, sqlDsn)
    if err != nil {
        panic(err.Error())
    }
    return db
}

//InsertDmarcRecord def
func InsertDmarcRecord(record FlatDmarcRecord) {
    db := dbConn()

	insForm, err := db.Prepare("INSERT INTO dmarc_report(processedtime, msghash, clientid, orgname, dmarcdomain, sourceip, sourcecount, disposition, dmarcspf, dmarcdkim, headerfrom, dkimdomain, dkimresult, spfdomain, spfresult, provider, hostname) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		panic(err.Error())
	}
	insResult, err := insForm.Exec(time.Now(), record.MsgHash, record.ClientID, record.OrgName, record.DmarcDomain, record.SourceIP, record.SourceCount, record.Disposition, record.DmarcSPF, record.DmarcDkim, record.HeaderFrom, record.DkimDomain, record.DkimResult, record.SpfDomain, record.SpfResult, record.Provider, record.Hostname )
    if err != nil {
		panic(err.Error())
	}
	fmt.Println(insResult)
    defer db.Close()

}



func init() {
	
	serveCmd.PersistentFlags().StringVarP(&configPath, "config", "c",
	"/configs/dmarcd.conf.json", "Path toe the configuration file")
 
	
	rootCmd.AddCommand(serveCmd)
}

func sigHandler() {
	// handle SIGHUP for reloading the configuration while running
	signal.Notify(signalChannel,
		syscall.SIGHUP,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGINT,
		syscall.SIGKILL,
		syscall.SIGUSR1,
	)
	// Keep the daemon busy by waiting for signals to come
	for sig := range signalChannel {
		if sig == syscall.SIGHUP {
			//do something on sig up
			//d.ReloadConfigFile(configPath)
		} else if sig == syscall.SIGUSR1 {
			//do something on reload?
			//d.ReopenLogs()
		} else if sig == syscall.SIGTERM || sig == syscall.SIGQUIT || sig == syscall.SIGINT {
			//handle shutdown gracefully
			//mainlog.Infof("Shutdown signal caught")
			//d.Shutdown()
			//mainlog.Infof("Shutdown completed, exiting.")
			return
		} else {
			//handle unknown signal
			//mainlog.Infof("Shutdown, unknown signal caught")
			return
		}
	}
}

func serve(cmd *cobra.Command, args []string) {
		
	client, err := redis.DialURL("redis://:"+os.Getenv("REDISPASSWORD")+"@"+os.Getenv("REDISHOST")+":6379/0")

	if err != nil {
		fmt.Println(err)
	} else {
		
		// Check redis server is up
		reply, err := client.Do("PING")
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println(reply)
		}

		for {
			fmt.Println("Looking for a new Q item...")
			//Constantly listen for items in redis queue and pop them one at a time when found
			poppedItem, err := redis.Strings(client.Do("BRPOP", "message_queue", 0))

			//Instantiate MessageQueueObject placeholder
			messageItem := MessageQueueItem{}

			//Populate our MessageItem object from popped item string/json/data
			json.Unmarshal([]byte(poppedItem[1]), &messageItem)

			//Create new reader for handling raw message data receive from queue
			mailReader := strings.NewReader(messageItem.MessageData)
			
			//Parse raw data into email object
			msg, err := email.ParseMessage(mailReader)
			if err != nil {
				//could not parse email data for attachments
				fmt.Println(err)
			}

			// TESTING REMOVE
			whoisraw, err := whois.Whois("a27-57.smtp-out.us-west-2.amazonses.com")
			fmt.Println(whoisraw)

			//Iterate attachments
			for _, part := range msg.MessagesAll() {
				mediaType, _, err := part.Header.ContentType()
				switch mediaType {
				case "application/zip":
						// Unzip the attachment into reader
						fmt.Println("ZIP file detected")
					zipReader, err := zip.NewReader(bytes.NewReader(part.Body),int64(len(part.Body)))
					if err != nil {
						fmt.Println(err)
					} 

					for _, zf := range zipReader.File {

						src, err := zf.Open()
						if err != nil {
							// err
						}
						defer src.Close()

						//Instantiate a new instance of DmarcReport
						var dmarcReport = new(DmarcReport)

						//Initialize decoder with unzipped buffer
						xmlDecoder := xml.NewDecoder(src)

						//Decode the xml data and populate DmarcReport object
						xmlDecoder.Decode(dmarcReport)

						//Debug output
						//fmt.Println(dmarcReport.Record[0].Row.SourceIP)

						
						
						for i := 0; i < len(dmarcReport.Record); i++ {
							hostname := ""
							providerOrg := ""

							resolver, err := net.LookupAddr(dmarcReport.Record[i].Row.SourceIP)
							if err != nil {
								fmt.Println(err)
								hostname = "unknown"
							} else {
								hostname = resolver[0]
								if hostname != "" {
									whoisraw, err := whois.Whois(hostname)
									fmt.Println(err)
									if err != nil {
										fmt.Println(err)
										providerOrg = "not avail"
									} else {
										reader := bytes.NewReader([]byte(whoisraw))
										scanner := bufio.NewScanner(reader)
										// Scan lines
										scanner.Split(bufio.ScanLines)

										// Scan through lines and find refer server
										for scanner.Scan() {
											line := scanner.Text()

											if strings.Contains(line, "OrgName:") {
												// Trim the refer: on left
												providerOrg = strings.TrimPrefix(line, "OrgName:")
												// Trim whitespace
												providerOrg = strings.TrimSpace(providerOrg)
											}
										}
									}
								}
							}

							dkimProcessed := DmarcRecordDkimAuthResult{
								Domain: "Not Present",
								Result: "Not Present",
							}
			
							if len(dmarcReport.Record[i].AuthResults.Dkim) > 0 {
								dkimProcessed = DmarcRecordDkimAuthResult{
									Domain: dmarcReport.Record[i].AuthResults.Dkim[0].Domain,
									Result: dmarcReport.Record[i].AuthResults.Dkim[0].Result,
								}
							}


							report := FlatDmarcRecord{
								MsgHash: messageItem.Hash,
								ClientID: messageItem.ClientID,
								OrgName: dmarcReport.Metadata.OrgName,
								DmarcDomain: dmarcReport.Policy.Domain,
								SourceIP: dmarcReport.Record[i].Row.SourceIP,
								SourceCount: dmarcReport.Record[i].Row.Count,
								Disposition: dmarcReport.Record[i].Row.PolicyEvaluated.Disposition,
								DmarcSPF: dmarcReport.Record[i].Row.PolicyEvaluated.Spf,
								DmarcDkim: dmarcReport.Record[i].Row.PolicyEvaluated.Dkim,
								HeaderFrom: dmarcReport.Record[i].Identifiers.HeaderFrom,
								DkimDomain: dkimProcessed.Domain,
								DkimResult: dkimProcessed.Result,
								SpfDomain: dmarcReport.Record[i].AuthResults.Spf.Domain,
								SpfResult: dmarcReport.Record[i].AuthResults.Spf.Result,
								Provider: providerOrg,
								Hostname: hostname,
							}
							fmt.Println(report)
							InsertDmarcRecord(report)
						}
					} 
				case "application/gzip":
						// Unzip the attachment into reader
					gzipReader, err := gzip.NewReader(bytes.NewReader(part.Body))
					if err != nil {
						fmt.Println(err)
					} 
					defer gzipReader.Close()
					
					//Instantiate a new instance of DmarcReport
					var dmarcReport = new(DmarcReport)

					//Initialize decoder with unzipped buffer
					xmlDecoder := xml.NewDecoder(gzipReader)

					//Decode the xml data and populate DmarcReport object
					xmlDecoder.Decode(dmarcReport)

					//Debug output
					fmt.Println(dmarcReport.Record[0].Row.SourceIP)
					for i := 0; i < len(dmarcReport.Record); i++ {

						hostname := ""
						providerOrg := ""

						resolver, err := net.LookupAddr(dmarcReport.Record[i].Row.SourceIP)
						if err != nil {
							fmt.Println(err)
							hostname = "unknown"
						} else {
							hostname = resolver[0]
							if hostname != "" {
								whoisraw, err := whois.Whois(hostname)
								fmt.Println(err)
								if err != nil {
									fmt.Println(err)
									providerOrg = "not avail"
								} else {
									reader := bytes.NewReader([]byte(whoisraw))
									scanner := bufio.NewScanner(reader)
									// Scan lines
									scanner.Split(bufio.ScanLines)

									// Scan through lines and find refer server
									for scanner.Scan() {
										line := scanner.Text()

										if strings.Contains(line, "OrgName:") {
											// Trim the refer: on left
											providerOrg = strings.TrimPrefix(line, "OrgName:")
											// Trim whitespace
											providerOrg = strings.TrimSpace(providerOrg)
										}
									}
								}
							}
						}
						
						

						dkimProcessed := DmarcRecordDkimAuthResult{
							Domain: "Not Present",
							Result: "Not Present",
						}
		
						if len(dmarcReport.Record[i].AuthResults.Dkim) > 0 {
							dkimProcessed = DmarcRecordDkimAuthResult{
								Domain: dmarcReport.Record[i].AuthResults.Dkim[0].Domain,
								Result: dmarcReport.Record[i].AuthResults.Dkim[0].Result,
							}
						}


						report := FlatDmarcRecord{
							MsgHash: messageItem.Hash,
							ClientID: messageItem.ClientID,
							OrgName: dmarcReport.Metadata.OrgName,
							DmarcDomain: dmarcReport.Policy.Domain,
							SourceIP: dmarcReport.Record[i].Row.SourceIP,
							SourceCount: dmarcReport.Record[i].Row.Count,
							Disposition: dmarcReport.Record[i].Row.PolicyEvaluated.Disposition,
							DmarcSPF: dmarcReport.Record[i].Row.PolicyEvaluated.Spf,
							DmarcDkim: dmarcReport.Record[i].Row.PolicyEvaluated.Dkim,
							HeaderFrom: dmarcReport.Record[i].Identifiers.HeaderFrom,
							DkimDomain: dkimProcessed.Domain,
							DkimResult: dkimProcessed.Result,
							SpfDomain: dmarcReport.Record[i].AuthResults.Spf.Domain,
							SpfResult: dmarcReport.Record[i].AuthResults.Spf.Result,
							Provider: providerOrg,
							Hostname: hostname,
						}
						InsertDmarcRecord(report)
					}
				default :
					fmt.Println(string(part.Body))
				}

				if err != nil {
					fmt.Println(err)
				} 
				

				//msghash, identifiers.from, row.sourceip, row.count, row.policy.dkim, row.policy.spf, row.policy.disposition
				//GET COUNTRY/GEO LOCATION FOR SOURCE IP
			}

			if err != nil {
				log.Fatal(err)
			} else {
				fmt.Println("Popped from queue for processing: " + messageItem.Hash)
			}
			
		}
		sigHandler()
	}

}

