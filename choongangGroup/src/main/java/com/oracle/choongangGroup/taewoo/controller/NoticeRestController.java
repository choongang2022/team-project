package com.oracle.choongangGroup.taewoo.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.oracle.choongangGroup.taewoo.domain.Notice;
import com.oracle.choongangGroup.taewoo.repository.NoticeJpaRepository;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class NoticeRestController {
	
	public final NoticeJpaRepository noticeJpaRepository;
	
	// 글 수정
	@RequestMapping(value = "/manager/updateNotice")
	public String noticeUpdate(Notice notice) {
		System.out.println("noticeUpdate start....");
		noticeJpaRepository.save(notice);
		return null;
	}

}
