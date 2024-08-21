package com.tujuhsembilan.example.controller;

import java.util.stream.Collectors;

import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.tujuhsembilan.example.controller.dto.NoteDto;
import com.tujuhsembilan.example.model.Note;
import com.tujuhsembilan.example.repository.NoteRepo;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/note")
@RequiredArgsConstructor
public class NoteController {

  private final NoteRepo repo;

  private final ModelMapper mdlMap;

  @GetMapping
  public ResponseEntity<?> getNotes() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    boolean isAdmin = authentication.getAuthorities().stream()
        .anyMatch(authority -> authority.getAuthority().equals("ADMIN"));
    if(isAdmin){
      return ResponseEntity
      .ok(repo.findAll()
          .stream()
          .map(o -> mdlMap.map(o, NoteDto.class))
          .collect(Collectors.toSet()));
    }
    else{
      String currentUsername = authentication.getName();
      return ResponseEntity
      .ok(repo.findByCreatedBy(currentUsername)
          .stream()
          .map(o -> mdlMap.map(o, NoteDto.class))
          .collect(Collectors.toSet()));
    }
    
  }

  @PostMapping
  public ResponseEntity<?> saveNote(@RequestBody NoteDto body) {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    String currentUsername = authentication.getName();
    var newNote = mdlMap.map(body, Note.class);
    newNote.setCreatedBy(currentUsername);
    newNote = repo.save(newNote);
    return ResponseEntity.status(HttpStatus.CREATED).body(newNote);
  }

}
