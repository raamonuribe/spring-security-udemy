package com.ramonuribe.supportportal.service.impl;

import com.ramonuribe.supportportal.domain.User;
import com.ramonuribe.supportportal.domain.UserPrincipal;
import com.ramonuribe.supportportal.repository.UserRepository;
import com.ramonuribe.supportportal.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Date;


@Service
@Transactional
public class UserServiceImpl implements UserService, UserDetailsService {
    private Logger logger = LoggerFactory.getLogger(getClass());
    private UserRepository repository;


    public UserServiceImpl(UserRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = repository.findUserByUsername(username);
        if (user == null) {
            logger.error("User not found by username " + username);
            throw new UsernameNotFoundException("User not found by username " + username);
        } else {
            user.setLastLoginDateDisplay(user.getLastLoginDate());
            user.setLastLoginDate(new Date());
            // We're saving user because we updated the last login date
            repository.save(user);
            UserPrincipal userPrincipal = new UserPrincipal(user);
            logger.info("Found User with username: " + username);

            return userPrincipal;

        }
    }
}
