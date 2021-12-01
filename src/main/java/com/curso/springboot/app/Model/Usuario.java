package com.curso.springboot.app.Model;


import javax.persistence.*;
import java.util.List;

@Entity
@Table(name="users")
public class Usuario {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, length = 45)
    private String username;
    @Column(length = 60)
    private String password;

    private Boolean enabled;

    @OneToMany(fetch =FetchType.LAZY, cascade = CascadeType.ALL) //Un usuario puede tener muchos roles
    @JoinColumn(name = "user_id")
    private List<Role> roles;


    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public List<Role> getRoles() {
        return roles;
    }

    public void setRoles(List<Role> roles) {
        this.roles = roles;
    }

    public void setId(Long id) {
        this.id = id;
    }


    public Long getId() {
        return id;
    }
}
