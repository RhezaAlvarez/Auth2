package com.tujuhsembilan.example.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tujuhsembilan.example.model.BlackListToken;

@Repository
public interface BlackListTokenRepo extends JpaRepository<BlackListToken, String>{
    
}
