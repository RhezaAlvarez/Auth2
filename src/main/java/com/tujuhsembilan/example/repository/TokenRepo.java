package com.tujuhsembilan.example.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tujuhsembilan.example.model.Token;

@Repository
public interface TokenRepo extends JpaRepository<Token, String>{
    
}
