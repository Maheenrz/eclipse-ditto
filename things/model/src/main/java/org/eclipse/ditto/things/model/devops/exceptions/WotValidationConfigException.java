/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.eclipse.ditto.things.model.devops.exceptions;

/**
 * Aggregates all DittoRuntimeExceptions which are related to WoT validation config.
 * @since 3.8.0
 */
public interface WotValidationConfigException {
    /**
     * Error code prefix of errors related to WoT validation config.
     */
    String ERROR_CODE_PREFIX = "wot.validation.config:";
} 