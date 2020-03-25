package main

import (
	"github.com/jinzhu/gorm"
	m "scaha-entity-model"
)

type DAO struct {
	DB *gorm.DB
}

//
// Here are some simple DAO routines that will
// Lets find a profile and everone underneath it
func (d DAO) FindProfile(usercode string, pwd string) (*m.Profile, error) {
	var profile = m.Profile{}
	err := d.DB.Debug().Where("user_code = ? AND pwd = ?", usercode, pwd).
		Preload("Person").
		Preload("Roles").
		Preload("Roles.InheritedRoles").
		Preload("Roles.InheritedRoles.InheritedRoles").
		First(&profile).Error
	r := profile.Roles
	profile.Roles = *r.Flatten()
	return &profile, err
}

//
// Here are some simple DAO routines that will
// Lets find a profile and everone underneath it
func (d DAO) DoesProfileExist(profileid uint) (bool, error) {
	var profile = m.Profile{}
	err := d.DB.Debug().Where("id = ?", profileid).
		First(&profile).Error
	return profile.ID != 0, err
}
