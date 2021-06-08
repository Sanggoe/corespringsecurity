package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.entity.Resources;

import java.util.List;

public interface ResourcesService {

    Resources getResources(long id);

    List<Resources> getResources();

    void createResources(Resources resources);

    void deleteResources(long id);
}
