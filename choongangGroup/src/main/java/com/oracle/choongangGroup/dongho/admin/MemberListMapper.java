package com.oracle.choongangGroup.dongho.admin;

import java.util.ArrayList;
import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface MemberListMapper {

	List<MemberPagingDto> memberPaging(Criteria criteria);
	
	@Select("SELECT COUNT(*) FROM member")
	int memberCount();

	int deleteMember(@Param("deleteIdList") ArrayList<String> deleteIdList);

}
