package misp4go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/levigross/grequests"
	"time"
)

type Mispdata struct {
	Url    string
	Apikey string
	Ro     grequests.RequestOptions
}

type Org struct {
	Id   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Uuid string `json:"uuid,omitempty"`
}

type attributeReturn struct {
	Attribute Attribute `json:"Attribute"`
	Raw       []byte    `json:"-"`
}

// Missing: ObjectRelation, ShadowAttribute
type Attribute struct {
	Id                  string `json:"id"`
	Type                string `json:"type"`
	Category            string `json:"category"`
	ToIds               bool   `json:"to_ids"`
	Uuid                string `json:"uuid"`
	EventId             string `json:"event_id"`
	Distribution        string `json:"distribution"`
	Comment             string `json:"comment"`
	Timestamp           string `json:"timestamp"`
	SharingGroupid      string `json:"sharing_group_id"`
	Deleted             bool   `json:"deleted"`
	DisabledCorrelation bool   `json:"disable_correlation"`
	ObjectId            string `json:"object_id"`
	Value               string `json:"value"`
}

// Missing: ShadowAttribute, RelatedEvent, Galaxy, Object
type Event struct {
	Id                 string      `json:"id,omitempty"`
	OrgcId             string      `json:"orgc_id,omitempty"`
	OrgId              string      `json:"org_id,omitempty"`
	Date               string      `json:"date,omitempty"`
	ThreatLevelId      string      `json:"threat_level_id,omitempty"`
	Info               string      `json:"info,omitempty"`
	Published          bool        `json:"published,omitempty"`
	Uuid               string      `json:"uuid,omitempty"`
	AttributeCount     string      `json:"attribute_count,omitempty"`
	Analysis           string      `json:"analysis,omitempty"`
	Timestamp          string      `json:"timestamp,omitempty"`
	Distribution       string      `json:"distribution,omitempty"`
	ProposalEmailLock  bool        `json:"proposal_email_lock,omitempty"`
	Locked             bool        `json:"locked,omitempty"`
	PublishedTimestamp string      `json:"published_timestamp,omitempty"`
	SharingGroupId     string      `json:"sharing_group_id,omitempty"`
	DisableCorrelation bool        `json:"disable_correlation,omitempty"`
	EventCreatorEmail  string      `json:"event_creator_email,omitempty"`
	Attribute          []Attribute `json:"Attribute,omitempty"`
}

// FIXME - are these necessary? They break post requests.
//Org                Org         `json:"Org,omitempty"`
//Orgc               Org         `json:"Orgc,omitempty"`

type EventResp struct {
	Event Event `json:"Event"`
	Raw   []byte
}

// Defines API login principles that can be reused in requests
// Takes three parameters:
//  1. URL string
//  2. API key
//  3. Verify boolean that should be true in order to verify the servers certificate
// Returns Mispdata struct
func CreateLogin(inurl string, apikey string, verify bool) Mispdata {
	return Mispdata{
		Url:    inurl,
		Apikey: apikey,
		Ro: grequests.RequestOptions{
			Headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": apikey,
				"Accept":        "application/json",
			},
			RequestTimeout:     time.Duration(60) * time.Second,
			InsecureSkipVerify: !verify,
		},
	}
}

// Function for grabbing an event based on ID
// Takes one parameter:
// 1. eventId string
// Returns Event struct
func (misp *Mispdata) GetEvent(eventId string) (*EventResp, error) {
	formattedUrl := fmt.Sprintf("%s/events/%s", misp.Url, eventId)
	ret, err := grequests.Get(formattedUrl, &misp.Ro)

	parsedRet := new(EventResp)
	_ = json.Unmarshal(ret.Bytes(), parsedRet)
	parsedRet.Raw = ret.Bytes()

	return parsedRet, err
}

// Function for creating an event
// Takes one parameter:
// 1. Event struct
// Returns EventRet struct
func (misp *Mispdata) CreateEvent(event Event) (*EventResp, error) {
	formattedUrl := fmt.Sprintf("%s/events", misp.Url)

	jsondata, err := json.Marshal(event)
	if err != nil {
		fmt.Println(err)
	}

	// Reformatted
	realEvent := fmt.Sprintf(`{"Event": %s}`, jsondata)

	if err != nil {
		fmt.Println(err)
	}

	misp.Ro.RequestBody = bytes.NewReader([]byte(realEvent))
	ret, err := grequests.Post(formattedUrl, &misp.Ro)

	parsedRet := new(EventResp)
	_ = json.Unmarshal(ret.Bytes(), &parsedRet)
	parsedRet.Raw = ret.Bytes()

	return parsedRet, err
}

// Function for adding attributes to an event
// Takes two parameters:
// 1. eventId string
// 2. []attributes struct
// Returns Event struct
func (misp *Mispdata) AddAttributeToEvent(eventId string, attributes []Attribute) (*attributeReturn, error) {
	///attributes/add/eventId
	formattedUrl := fmt.Sprintf("%s/attributes/add/%s", misp.Url, eventId)

	jsondata, err := json.Marshal(attributes)
	if err != nil {
		return nil, err
	}

	misp.Ro.RequestBody = bytes.NewReader(jsondata)

	ret, err := grequests.Post(formattedUrl, &misp.Ro)

	parsedRet := new(attributeReturn)
	_ = json.Unmarshal(ret.Bytes(), &parsedRet)
	parsedRet.Raw = ret.Bytes()

	return parsedRet, err
}
