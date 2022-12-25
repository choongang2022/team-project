package com.oracle.choongangGroup.taewoo.repository;


import java.util.List;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.oracle.choongangGroup.changhun.JPA.Member;
import com.oracle.choongangGroup.taewoo.domain.Message;

public interface MessageRepository extends JpaRepository<Message, Long> {
	List<Message> findAllByReceiver(Member member);

	@Modifying
	@Query("DELETE FROM Message t WHERE t.messageId = :messageId")
	int deleteByMessageId(@Param("messageId") Long messageId);

	Message findByMessageId(Long messageId);

	List<Message> findByReceiverOrderByMessageIdDesc(Member member, Pageable pageable);

}
