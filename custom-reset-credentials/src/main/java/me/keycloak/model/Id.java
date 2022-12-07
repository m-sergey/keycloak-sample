package me.keycloak.model;

public class Id {

    //  System's code
    private String code;

    // User's id in that system
    private String id;

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Id(String code, String id) {
        this.code = code;
        this.id = id;
    }
}
