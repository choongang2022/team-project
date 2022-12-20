package com.oracle.choongangGroup.taewoo.repository;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.oracle.choongangGroup.taewoo.domain.Notice;

@Repository
public interface NoticeJpaRepository extends JpaRepository<Notice, Long> {
	// 검색기능
	List<Notice> findBynoticeTitleContaining(String keyword);

	@Modifying
	@Query("update Notice n set n.noticeHit = n.noticeHit + 1 where n.noticeNum = :noticeNum")
	int updateHit(@Param(value = "noticeNum") Long noticeNum);
	
	
	Page<Notice> findByNoticeType(PageRequest of, String NoticeType);

	Page<Notice> findByNoticeTypeOrNoticeType(PageRequest of, String noticeType, String allcontent);

	

	
	
	
	
	



}
