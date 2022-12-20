package com.oracle.choongangGroup.taewoo.service;



import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.NoSuchElementException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.changhun.address.MemberRepository;
import com.oracle.choongangGroup.taewoo.domain.Notice;
import com.oracle.choongangGroup.taewoo.dto.NoticeDto;
import com.oracle.choongangGroup.taewoo.repository.NoticeJpaRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
@Transactional
public class NoticeService {
	
	private final MemberRepository memberRepository; 
	private final NoticeJpaRepository noticeJpaRepository;
	private final static String VIEWCOOKIENAME = "alreadyViewCookie";

	public Notice findById(Long noticeNum) {
		System.out.println("NoticeService findById start....");	
		Notice notice = noticeJpaRepository.findById(noticeNum).orElseThrow(() -> new NoSuchElementException());
		return notice;
	}

	public List<Notice> searchNotice(String keyword) {
		System.out.println("NoticeService searchNotice start....");
		
		List<Notice> searchNoticeList = noticeJpaRepository.findBynoticeTitleContaining(keyword);
		
		return searchNoticeList;
	}
	
	
	public int updateHit(Long noticeNum, HttpServletRequest request, HttpServletResponse response) {
		System.out.println("noticeNum -->" + noticeNum);
		System.out.println("updateHit start");
		Cookie[] cookies = request.getCookies();
		boolean checkCookie = false;
		int result = 0;
		if(cookies != null) {
			for (Cookie cookie : cookies) {
				// 조회한 경우 체크
				if(cookie.getName().equals(VIEWCOOKIENAME+noticeNum)) checkCookie = true;
				System.out.println(cookies);
			}
			if (!checkCookie) {
				Cookie newCookie = createCookieForForNotOverLap(noticeNum);
				response.addCookie(newCookie);
				result = noticeJpaRepository.updateHit(noticeNum);
				System.out.println(result);
			}
		} else {
			Cookie newCookie = createCookieForForNotOverLap(noticeNum);
			response.addCookie(newCookie);
			result = noticeJpaRepository.updateHit(noticeNum);
			System.out.println(result);
		}
		return result;
	}

	/*
	 * 조회수 중복 방지를 위한 쿠키 생성 메소드
	 * @param cookie
	 * @return
	 */		
	private Cookie createCookieForForNotOverLap(Long noticeNum) {
		Cookie cookie = new Cookie(VIEWCOOKIENAME+noticeNum, String.valueOf(noticeNum));
		cookie.setComment("조회수 중복 증가 방지 쿠키");  	// 쿠키 용도 설명
		cookie.setMaxAge(getRemainSecondForTommorow());	 	// 하루를 준다.
		cookie.setHttpOnly(true); 							// 서버에서만 조작가능
		return cookie;
	}
	
	// 다음 날 정각까지 남은 시간(초)
	private int getRemainSecondForTommorow() {
		LocalDateTime now = LocalDateTime.now();
		LocalDateTime tommorow = LocalDateTime.now().plusDays(1L).truncatedTo(ChronoUnit.DAYS);
		return (int) now.until(tommorow, ChronoUnit.SECONDS);
	}

	public void updateNotice(Notice notice) {
		System.out.println("updateNotice start....");
		System.out.println(notice.getNoticeNum());
		System.out.println(notice.getNoticeTitle());
		System.out.println(notice.getNoticeContent());
		Notice notice2 = new Notice();
		notice2.setNoticeNum(notice.getNoticeNum());
		notice2.setNoticeTitle(notice.getNoticeTitle());
//		notice2.setNoticeContent(notice.getNoticeContent());
		noticeJpaRepository.save(notice2);
		
	}

	public NoticeDto write(NoticeDto noticeDto, String writerUserid) {
		System.out.println("NoticeService write start....");
		Member writer = memberRepository.findByUserid(writerUserid);

		Notice notice = new Notice();
		notice.setWriter(writer);
		notice.setNoticeTitle(noticeDto.getNoticeTitle());
		notice.setNoticeContent(noticeDto.getNoticeContent());
		notice.setNoticeType(noticeDto.getNoticeType());
		noticeJpaRepository.save(notice);
		
		return NoticeDto.toDto(notice);
	}

	public Notice update(NoticeDto noticeDto, String writerUserid) {
		System.out.println("update start....");
		Member writer = memberRepository.findByUserid(writerUserid);
		Notice notice = new Notice();
		notice.setNoticeNum(noticeDto.getNoticeNum());
		notice.setWriter(writer);
		notice.setNoticeTitle(noticeDto.getNoticeTitle());
		notice.setNoticeContent(noticeDto.getNoticeContent());
		notice.setNoticeType(noticeDto.getNoticeType());
		return noticeJpaRepository.save(notice);
		
	}


	

	
}
