package repository

import (
	"github.com/jinzhu/gorm"
	log "github.com/sirupsen/logrus"
	m "scaha_micro_member/model"
)

type DAO struct {
	DB *gorm.DB
}

//
// Here are some simple DAO routines that will
func (d DAO) FindAll(persons *[]m.Person) error {
	return d.DB.Find(persons).Error
}

//
// Here are some simple DAO routines that will
// Lets find a person
func (d DAO) FindPerson(id int) (*m.Person, error) {
	var person = m.Person{}
	err := d.DB.Debug().Preload("Profile").Where("id = ?", id).First(&person).Error
	return &person, err
}

//
// Here are some simple DAO routines that will
// Lets find a person
func (d DAO) FindPersonByProfile(profile m.Profile) (*m.Person, error) {
	var person = m.Person{}
	err := d.DB.Debug().Preload("Profile").Where("id_profile = ?", profile.ID).First(&person).Error

	log.Debug(err)

	return &person, err
}

//
// Here are some simple DAO routines that will
// Lets find a profile and everone underneath it
func (d DAO) FindProfile(usercode string, pwd string) (*m.Profile, error) {
	var profile = m.Profile{}
	err := d.DB.Debug().Where("user_code = ? AND pwd = ?", usercode, pwd).First(&profile).Error
	return &profile, err
}
//
// Here are some simple DAO routines that will
// Lets find a person
// We want to control exactly how these structures get loaded because of the recursive nature of this.
//
func (d DAO) FindFamily(id int) (*m.Family, error) {
	var family = m.Family{}
	err := d.DB.Debug().
		Where("id = ?", id).
		Preload("Person").
		Preload("Person.Profile").
		Preload("FamilyMembers").
		Preload("FamilyMembers.Person").
		First(&family).Error
	return &family, err
}

func (d DAO) FindFamilyByPerson(person m.Person) (*m.Family, error) {
	var family = m.Family{}
	err := d.DB.Debug().
		Where("id_person = ?", person.ID).
		Preload("Person").
		Preload("Person.UsaHockeys").
		Preload("Person.Profile").
		Preload("FamilyMembers").
		Preload("FamilyMembers.Person").
		Preload("FamilyMembers.Person.Profile").
		Preload("FamilyMembers.Person.UsaHockeys").
		First(&family).Error
	return &family, err
}

//
// Here are some simple DAO routines that will
// Lets find a person
func (d DAO) FindFamilyMemberByFamilyId(id int) (*m.FamilyMember, error) {
	var familymember = m.FamilyMember{}
	err := d.DB.Debug().Where("id_family = ?", id).
		First(&familymember).Error
	return &familymember, err
}


func (d DAO) Create(person *m.Person) error {
	return d.DB.Create(person).Error
}

func (d DAO) FindByPage(person *[]m.Person, page, view int) error {
	return d.DB.Limit(view).Offset(view * (page - 1)).Find(&person).Error

}

func (d DAO) UpdateByName(name, email string) error {
	var person m.Person
	d.DB.Where("name=?", name).Find(&person)
	person.Email = email
	return d.DB.Save(&person).Error
}

func (d DAO) DeleteByName(name string) error {
	var person m.Person
	d.DB.Where("name=?", name).Find(&person)
	return d.DB.Delete(&person).Error
}

