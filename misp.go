package misp4go

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/levigross/grequests"
	"strings"
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
	Attribute Attribute              `json:"Attribute"`
	Errors    map[string]interface{} `json:"errors"`
	Raw       []byte                 `json:"-"`
}

type Attribute struct {
	ID                 string      `json:"id,omitempty"`
	Type               string      `json:"type,omitempty"`
	Category           string      `json:"category,omitempty"`
	ToIds              bool        `json:"to_ids,omitempty"`
	UUID               string      `json:"uuid,omitempty"`
	EventID            string      `json:"event_id,omitempty"`
	Distribution       string      `json:"distribution,omitempty"`
	Timestamp          string      `json:"timestamp,omitempty"`
	Comment            string      `json:"comment,omitempty"`
	SharingGroupID     string      `json:"sharing_group_id,omitempty"`
	Deleted            bool        `json:"deleted,omitempty"`
	DisableCorrelation bool        `json:"disable_correlation,omitempty"`
	ObjectID           string      `json:"object_id,omitempty"`
	ObjectRelation     interface{} `json:"object_relation,omitempty"`
	Value              string      `json:"value,omitempty"`
	Sighting           []Sighting  `json:"Sighting,omitempty"`
}

type Tag struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	Colour         string      `json:"colour"`
	Exportable     bool        `json:"exportable"`
	UserID         string      `json:"user_id"`
	HideTag        bool        `json:"hide_tag"`
	NumericalValue interface{} `json:"numerical_value"`
}

type Sighting struct {
	ID            string `json:"id"`
	AttributeID   string `json:"attribute_id"`
	EventID       string `json:"event_id"`
	OrgID         string `json:"org_id"`
	DateSighting  string `json:"date_sighting"`
	UUID          string `json:"uuid"`
	Source        string `json:"source"`
	Type          string `json:"type"`
	Organisation  Org    `json:"Organisation"`
	AttributeUUID string `json:"attribute_uuid"`
}

type EventWrapper struct {
	Events []EventRet `json:"-"`
	Raw    []byte     `json:"-"`
}

type EventRet struct {
	Id                 string      `json:"id"`
	OrgID              string      `json:"org_id"`
	Date               string      `json:"date"`
	Info               string      `json:"info"`
	UUID               string      `json:"uuid"`
	Published          bool        `json:"published"`
	Analysis           string      `json:"analysis"`
	AttributeCount     string      `json:"attribute_count"`
	OrgcID             string      `json:"orgc_id"`
	Timestamp          string      `json:"timestamp"`
	Distribution       string      `json:"distribution"`
	SharingGroupID     string      `json:"sharing_group_id"`
	ProposalEmailLock  bool        `json:"proposal_email_lock"`
	Locked             bool        `json:"locked"`
	ThreatLevelID      string      `json:"threat_level_id"`
	PublishTimestamp   string      `json:"publish_timestamp"`
	DisableCorrelation bool        `json:"disable_correlation"`
	Attribute          []Attribute `json:"Attribute"`
	ExtendsUUID        string      `json:"extends_uuid"`
	Org                Org         `json:"Org"`
	Orgc               Orgc        `json:"orgc"`
	EventTag           []EventTag  `json:"orgc"`
	Raw                []byte      `json:"-,omitempty"`
}

type Orgc struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

type EventTag struct {
	ID      string `json:"id"`
	EventID string `json:"event_id"`
	TagID   string `json:"tag_id"`
	Tag     Tag    `json:"Tag"`
}

//// Missing: ShadowAttribute, RelatedEvent, Galaxy, Object
type Event struct {
	Id                 string `json:"id,omitempty"`
	OrgcId             string `json:"orgc_id,omitempty"`
	OrgId              string `json:"org_id,omitempty"`
	Date               string `json:"date,omitempty"`
	ThreatLevelId      string `json:"threat_level_id,omitempty"`
	Info               string `json:"info,omitempty"`
	Published          bool   `json:"published,omitempty"`
	Uuid               string `json:"uuid,omitempty"`
	AttributeCount     string `json:"attribute_count,omitempty"`
	Analysis           string `json:"analysis,omitempty"`
	Timestamp          string `json:"timestamp,omitempty"`
	Distribution       string `json:"distribution,omitempty"`
	ProposalEmailLock  bool   `json:"proposal_email_lock,omitempty"`
	Locked             bool   `json:"locked,omitempty"`
	PublishedTimestamp string `json:"published_timestamp,omitempty"`
	SharingGroupId     string `json:"sharing_group_id,omitempty"`
	DisableCorrelation bool   `json:"disable_correlation,omitempty"`
	EventCreatorEmail  string `json:"event_creator_email,omitempty"`
}

// FIXME - are these necessary? They break post requests.
//Org                Org         `json:"Org,omitempty"`
//Orgc               Org         `json:"Orgc,omitempty"`

type EventResp struct {
	Event EventRet `json:"Event"`
	Raw   []byte   `json:"-"`
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
	err = json.Unmarshal(ret.Bytes(), parsedRet)
	if err != nil {
		fmt.Println(err)
		return parsedRet, err
	}

	parsedRet.Raw = ret.Bytes()

	return parsedRet, err
}

// searching based on raw search
func (misp *Mispdata) SearchEventTag(tag string) (*EventWrapper, error) {
	var url string
	url = fmt.Sprintf("%s/events/index/searchtag:%s", misp.Url, tag)

	ret, err := grequests.Post(url, &misp.Ro)

	parsedRet := new(EventWrapper)
	err = json.Unmarshal(ret.Bytes(), &parsedRet.Events)

	if err != nil {
		return &EventWrapper{}, err
	}

	parsedRet.Raw = ret.Bytes()

	return parsedRet, nil
}

// searching based on raw search
func (misp *Mispdata) SearchAttributesRaw(search []byte) {
	var url string
	url = fmt.Sprintf("%s%s", misp.Url, "/attributes/restSearch")

	misp.Ro.JSON = search

	ret, err := grequests.Post(url, &misp.Ro)
	fmt.Println(ret, err)

}

// Function for creating an event
// Takes one parameter:
// 1. Event struct
// Returns EventRet struct
func (misp *Mispdata) CreateEvent(event Event) (*EventResp, error) {
	formattedUrl := fmt.Sprintf("%s/events", misp.Url)

	jsondata, err := json.Marshal(event)
	if err != nil {
		fmt.Printf("Failed marshalling: %s", err)
		return &EventResp{}, err
	}

	// Reformatted
	realEvent := fmt.Sprintf(`{"Event": %s}`, jsondata)
	fmt.Println(realEvent)

	misp.Ro.RequestBody = bytes.NewReader([]byte(realEvent))
	ret, err := grequests.Post(formattedUrl, &misp.Ro)

	parsedRet := new(EventResp)
	err = json.Unmarshal(ret.Bytes(), &parsedRet)
	parsedRet.Raw = ret.Bytes()

	return parsedRet, err
}

// Function for adding attributes to an event
// Takes two parameters:
// 1. eventId string
// 2. []attributes struct
// Returns Event struct
func (misp *Mispdata) AddTagsToEvent(eventId string, tags []string) error {
	formattedUrl := fmt.Sprintf("%s/events/addTag/%s", misp.Url, eventId)
	for _, item := range tags {
		fmt.Println(item)
		data := fmt.Sprintf(`{"tag": "%s"}`, item)
		misp.Ro.RequestBody = bytes.NewReader([]byte(data))
		ret, err := grequests.Post(formattedUrl, &misp.Ro)
		fmt.Println(ret, err)
	}

	return nil
	//jsondata, err := json.Marshal(attributes)
	//if err != nil {
	//	return nil, err
	//}

	//misp.Ro.RequestBody = bytes.NewReader(jsondata)

	//ret, err := grequests.Post(formattedUrl, &misp.Ro)

	//parsedRet := new(attributeReturn)
	//_ = json.Unmarshal(ret.Bytes(), &parsedRet)
	//parsedRet.Raw = ret.Bytes()

	//return parsedRet, err
}

// https://www.misp.software/2017/02/16/Sighting-The-Next-Level.html
//func (misp *Mispdata) AddObject(attributeId string) error {
//	// Might need to find ID
//	formattedUrl := fmt.Sprintf("%s/sightings/add/%s", misp.Url, attributeId)
//
//	ret, err := grequests.Post(formattedUrl, &misp.Ro)
//	_ = ret
//
//	return err
//}

type OuterObjectTemplatesWrapper struct {
	Detail []ObjectTemplateWrapper
	Raw    []byte `json:"-"`
}

type ObjectTemplateWrapper struct {
	ObjectTemplate ObjectTemplate `json:"ObjectTemplate"`
	Org            Org            `json:"Organisation"`
}

type ObjectTemplate struct {
	ID           string `json:"id"`
	UserID       string `json:"user_id"`
	OrgID        string `json:"org_id"`
	UUID         string `json:"uuid"`
	Name         string `json:"name"`
	MetaCategory string `json:"meta-category"`
	Description  string `json:"description"`
	Version      string `json:"version"`
	Requirements struct {
		Required []string `json:"required"`
	} `json:"requirements"`
	Fixed  bool `json:"fixed"`
	Active bool `json:"active"`
}

// Add object to an event
func (misp *Mispdata) AddObject(eventId string, templateId string, jsondata []byte) error {
	// Might need to find ID
	formattedUrl := fmt.Sprintf("%s/objects/add/%s/%s", misp.Url, eventId, templateId)

	// Reformatted
	misp.Ro.RequestBody = bytes.NewReader(jsondata)
	ret, err := grequests.Post(formattedUrl, &misp.Ro)
	fmt.Println(ret)

	return err
}

// https://www.misp.software/2017/02/16/Sighting-The-Next-Level.html
func (misp *Mispdata) GetObjectTemplatesList() (*OuterObjectTemplatesWrapper, error) {
	// Might need to find ID
	formattedUrl := fmt.Sprintf("%s/objectTemplates", misp.Url)

	ret, err := grequests.Get(formattedUrl, &misp.Ro)
	parsedRet := new(OuterObjectTemplatesWrapper)
	err = json.Unmarshal(ret.Bytes(), &parsedRet.Detail)
	if err != nil {
		return &OuterObjectTemplatesWrapper{}, err
	}

	parsedRet.Raw = ret.Bytes()
	return parsedRet, err
}

// https://www.misp.software/2017/02/16/Sighting-The-Next-Level.html
func (misp *Mispdata) AddSighting(attributeId string) error {
	// Might need to find ID
	formattedUrl := fmt.Sprintf("%s/sightings/add/%s", misp.Url, attributeId)

	ret, err := grequests.Post(formattedUrl, &misp.Ro)
	_ = ret

	return err

}

// Function for adding attributes to an event
// Takes two parameters:
// 1. eventId string
// 2. []attributes struct
// Returns Event struct
func (misp *Mispdata) AddAttributesToEvent(eventId string, attributes []Attribute) (*attributeReturn, error) {
	///attributes/add/eventId
	formattedUrl := fmt.Sprintf("%s/attributes/add/%s", misp.Url, eventId)

	jsondata, err := json.Marshal(attributes)
	if err != nil {
		return nil, err
	}

	misp.Ro.RequestBody = bytes.NewReader(jsondata)

	ret, err := grequests.Post(formattedUrl, &misp.Ro)

	parsedRet := new(attributeReturn)
	err = json.Unmarshal(ret.Bytes(), &parsedRet)
	if err != nil {
		return &attributeReturn{}, err
	}

	parsedRet.Raw = ret.Bytes()

	if strings.Contains(string(parsedRet.Raw), "A similar attribute already exists for this event.") {
		return parsedRet, errors.New("Attribute already exists.")
	}

	return parsedRet, nil
}
